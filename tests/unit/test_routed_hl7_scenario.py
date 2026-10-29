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
from tapirxl.parser.envelope_builder import credit_ip_owner, learn_ip_owner
from tapirxl.parser.live_emitter import LiveEmitter
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


def test_owner_learned_from_arp_and_dhcp_ack_only() -> None:
    owners: dict[str, str] = {}
    learn_ip_owner(_rec("ARP", ROUTER_MAC, "10.0.0.5", spa="10.0.0.5", sha=LAB_MAC), owners)
    learn_ip_owner(_rec("ARP", LAB_MAC, "0.0.0.0", spa="0.0.0.0", sha=LAB_MAC), owners)  # probe
    learn_ip_owner(
        _rec("DHCP", ENGINE_MAC, "0.0.0.0", dhcp_message_type="ack", lease_yiaddr="10.0.0.6"),
        owners,
    )
    learn_ip_owner(
        _rec("DHCP", ROUTER_MAC, "0.0.0.0", dhcp_message_type="offer", lease_yiaddr="10.0.0.7"),
        owners,
    )
    learn_ip_owner(_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.8"), owners)
    assert owners == {"10.0.0.5": LAB_MAC.upper(), "10.0.0.6": ENGINE_MAC.upper()}


def test_unbound_ip_and_dhcp_keep_their_mac() -> None:
    owners = {"10.0.0.5": LAB_MAC.upper()}  # the router has claimed nothing
    for rec in (_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.9"), _rec("DHCP", ROUTER_MAC, "10.0.0.5")):
        credit_ip_owner(rec, owners, {})
        assert rec["src_mac"] == ROUTER_MAC


def test_live_mode_credits_the_owner() -> None:
    emitter = LiveEmitter({}, clock=lambda: 0.0)
    emitter.ingest_record(_rec("ARP", LAB_MAC, "10.0.0.5", spa="10.0.0.5", sha=LAB_MAC))
    emitter.ingest_record(_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.5"))
    assert set(emitter.hosts) == {LAB_MAC.upper()}


def test_live_drops_a_routed_copy_seen_before_its_owner() -> None:
    """The router has claimed its own IPs, the sender has not ARPed yet."""
    emitter = LiveEmitter({}, clock=lambda: 0.0)
    emitter.ingest_record(_rec("ARP", ROUTER_MAC, "10.0.0.1", spa="10.0.0.1", sha=ROUTER_MAC))
    emitter.ingest_record(_rec("HL7_MLLP", ROUTER_MAC, "10.0.0.5"))  # routed, owner unknown
    emitter.ingest_record(_rec("SSH", ROUTER_MAC, "10.0.0.1"))  # the router's own
    router = emitter.hosts[ROUTER_MAC.upper()].envelope
    assert not router.get("pipeline_3")
    assert router.get("pipeline_2") is not None


def test_unclaimed_mac_keeps_its_records() -> None:
    """A MAC that never ARPed is not known to be routing: nothing is dropped."""
    assert credit_ip_owner(_rec("HL7_MLLP", LAB_MAC, "10.0.0.9"), {}, {})
