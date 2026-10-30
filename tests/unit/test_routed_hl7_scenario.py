"""HL7 routed through a router-on-a-stick (tests/fixtures/routed_hl7_scenario.pcap).

Covers #37: the router's leg of a routed packet is filed under the host that
owns the source IP, so the router never collects clinical signals it only
forwards. See tests/fixtures/build_routed_hl7_scenario.py for the frames.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from tapirxl.cli import app
from tapirxl.parser.envelope_builder import IpOwners
from tapirxl.parser.live_emitter import LiveEmitter
from tapirxl.parser.pipeline import build_signal_register
from tapirxl.schemas.envelope import HostEnvelope

PCAP = Path(__file__).resolve().parents[1] / "fixtures/routed_hl7_scenario.pcap"

ROUTER_MAC = "00:1c:73:0a:00:01"
LAB_MAC = "00:0e:2f:40:00:02"
ENGINE_MAC = "00:50:56:0a:00:20"


@pytest.fixture(scope="module")
def envelopes() -> dict[str, HostEnvelope]:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    result = CliRunner().invoke(app, ["parse", str(PCAP)])
    assert result.exit_code == 0, result.output
    lines = [ln for ln in result.output.splitlines() if ln.strip().startswith("{")]
    return {e.host_id: e for e in (HostEnvelope.model_validate_json(ln) for ln in lines)}


def _hl7(env: HostEnvelope) -> list:
    return (env.pipeline_3.hl7 if env.pipeline_3 else None) or []


def test_router_collects_no_routed_hl7(envelopes: dict[str, HostEnvelope]) -> None:
    router = envelopes[ROUTER_MAC]
    assert _hl7(router) == []
    assert "HL7_CLINICAL_INTERFACE" not in router.triage.floor_triggers


def test_both_legs_credit_the_sender(envelopes: dict[str, HostEnvelope]) -> None:
    for mac in (LAB_MAC, ENGINE_MAC):
        assert len(_hl7(envelopes[mac])) == 2, mac  # own leg + the router's copy
        assert "HL7_CLINICAL_INTERFACE" in envelopes[mac].triage.floor_triggers


def test_router_keeps_its_own_traffic(envelopes: dict[str, HostEnvelope]) -> None:
    assert envelopes[ROUTER_MAC].pipeline_2 is not None  # its own SYN to port 22


def _rec(protocol: str, src_mac: str, src_ip: str, **raw: str) -> dict:
    return {"protocol": protocol, "src_mac": src_mac, "src_ip": src_ip, "raw_fields": raw}


def _owners(*recs: dict) -> IpOwners:
    owners = IpOwners()
    for r in recs:
        owners.learn(r)
    return owners


def _arp(mac: str, ip: str) -> dict:
    return _rec("ARP", mac, ip, spa=ip, sha=mac)


def test_owner_learned_from_arp_and_dhcp_ack_only() -> None:
    owners = _owners(
        _rec("ARP", ROUTER_MAC, "10.0.0.5", spa="10.0.0.5", sha=LAB_MAC),
        _rec("ARP", LAB_MAC, "0.0.0.0", spa="0.0.0.0", sha=LAB_MAC),  # probe
        _rec("DHCP", ENGINE_MAC, "0.0.0.0", dhcp_message_type="ack", lease_yiaddr="10.0.0.6"),
        _rec("DHCP", ROUTER_MAC, "0.0.0.0", dhcp_message_type="offer", lease_yiaddr="10.0.0.7"),
        _rec("HL7_MLLP", ROUTER_MAC, "10.0.0.8"),
    )
    assert owners.by_ip == {"10.0.0.5": LAB_MAC.upper(), "10.0.0.6": ENGINE_MAC.upper()}


def test_a_moved_ip_leaves_its_old_owner() -> None:
    owners = _owners(_arp(LAB_MAC, "10.0.0.5"), _arp(ENGINE_MAC, "10.0.0.5"))
    assert owners.by_mac[LAB_MAC.upper()] == set()
    assert owners.by_mac[ENGINE_MAC.upper()] == {"10.0.0.5"}


def test_unbound_ip_and_dhcp_keep_their_mac() -> None:
    owners = _owners(_arp(LAB_MAC, "10.0.0.5"))  # the router has claimed nothing
    for rec in (_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.9"), _rec("DHCP", ROUTER_MAC, "10.0.0.5")):
        assert owners.credit(rec, {})
        assert rec["src_mac"] == ROUTER_MAC


def test_live_mode_credits_the_owner() -> None:
    emitter = LiveEmitter({}, clock=lambda: 0.0)
    emitter.ingest_record(_arp(LAB_MAC, "10.0.0.5"))
    emitter.ingest_record(_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.5"))
    assert set(emitter.hosts) == {LAB_MAC.upper()}
    assert emitter.hosts[LAB_MAC.upper()].envelope.get("pipeline_3")  # the HL7 landed here


def _router_then_routed_copy() -> list[dict]:
    """The router claims two gateways; a routed copy arrives before its sender's ARP."""
    return [
        {**_arp(ROUTER_MAC, "10.0.0.1"), "timestamp": 1.0},
        {**_arp(ROUTER_MAC, "10.0.1.1"), "timestamp": 2.0},
        {**_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.5"), "timestamp": 3.0},  # routed, owner unknown
        {**_rec("SSH", ROUTER_MAC, "10.0.0.1"), "timestamp": 4.0},  # the router's own
        {**_arp(LAB_MAC, "10.0.0.5"), "timestamp": 5.0},  # the sender, too late
    ]


def test_live_drops_a_routed_copy_seen_before_its_owner() -> None:
    emitter = LiveEmitter({}, clock=lambda: 0.0)
    for r in _router_then_routed_copy():
        emitter.ingest_record(r)
    router = emitter.hosts[ROUTER_MAC.upper()].envelope
    assert not router.get("pipeline_3")
    assert router.get("pipeline_2") is not None


def test_batch_agrees_with_live_on_the_same_records() -> None:
    envs = {e["mac"]: e for e in build_signal_register(_router_then_routed_copy(), {})}
    assert not envs[ROUTER_MAC.upper()].get("pipeline_3")  # dropped, as in live mode
    assert not envs[LAB_MAC.upper()].get("pipeline_3")  # not re-credited from the future


def test_a_host_using_an_unannounced_address_keeps_its_traffic() -> None:
    """One claimed IP is an ordinary host, not a router: nothing is dropped."""
    owners = _owners(_arp(LAB_MAC, "10.0.0.5"))
    assert owners.credit(_rec("HL7_MLLP", LAB_MAC, "10.0.0.50"), {})


def test_unclaimed_mac_keeps_its_records() -> None:
    """A MAC that never ARPed is not known to be routing: nothing is dropped."""
    assert IpOwners().credit(_rec("HL7_MLLP", LAB_MAC, "10.0.0.9"), {})
