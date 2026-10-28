"""DHCP through a relay agent (tests/fixtures/dhcp_relay_scenario.pcap).

Two clients on two VLANs get leases through one router-on-a-stick relay; the
capture sees each client message twice (client broadcast, relay copy) and each
server reply twice (server -> relay, relay -> client). See the builder,
tests/fixtures/build_dhcp_relay_scenario.py, for the frame layout.

Relay attribution (docs/issues/dhcp-relay-attribution.md) is fixed: DHCP
records are keyed by chaddr. The remaining xfail is strict: when
docs/issues/dhcp-client-identity.md (option 53, yiaddr, hostname choice) is
fixed it XPASSes and fails the run, so its marker comes off with that fix.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tapirxl.cli import app
from tapirxl.parser.adapters.pyshark_source import PysharkSource
from tapirxl.parser.extractors import dhcp as dhcp_extractor
from tapirxl.schemas.envelope import HostEnvelope

PCAP = Path(__file__).resolve().parents[1] / "fixtures/dhcp_relay_scenario.pcap"

ROUTER_MAC = "00:1c:73:0a:00:01"
SERVER_MAC = "00:50:56:0a:00:12"
CLIENTS = {  # MAC -> (hostname, leased address)
    "00:09:fb:30:00:07": ("ICU-MON-07", "10.50.30.107"),
    "00:0e:2f:40:00:02": ("LAB-ANALYZER-02", "10.50.40.102"),
}

pytestmark = pytest.mark.skipif(not PCAP.exists(), reason=f"PCAP not found: {PCAP}")


def _run(*args: str) -> list[str]:
    result = CliRunner().invoke(app, ["parse", str(PCAP), *args])
    assert result.exit_code == 0, result.output
    return [line for line in result.output.splitlines() if line.strip().startswith("{")]


@pytest.fixture(scope="module")
def envelopes() -> dict[str, HostEnvelope]:
    envs = [HostEnvelope.model_validate_json(line) for line in _run()]
    return {e.host_id: e for e in envs}


@pytest.fixture(scope="module")
def inventory() -> dict[str, dict]:
    recs = [json.loads(line) for line in _run("--json")]
    return {r["mac_address"].lower(): r for r in recs}


def _option12(env: HostEnvelope) -> set[str]:
    dhcp = (env.pipeline_3.dhcp if env.pipeline_3 else None) or []
    return {d.option12_hostname for d in dhcp if d.option12_hostname}


# ── Holds today: the client's own broadcast is attributed correctly ──────────


def test_each_client_gets_its_own_hostname(inventory: dict[str, dict]) -> None:
    for mac, (hostname, _) in CLIENTS.items():
        assert inventory[mac]["hostname"] == hostname


# ── Relay attribution (docs/issues/dhcp-relay-attribution.md) ────────────────


def test_relay_router_gets_no_client_hostname(inventory: dict[str, dict]) -> None:
    router = inventory.get(ROUTER_MAC)
    assert router is None or router["hostname"] is None


def test_no_host_carries_another_hosts_option12(envelopes: dict[str, HostEnvelope]) -> None:
    for mac, env in envelopes.items():
        own = {CLIENTS[mac][0]} if mac in CLIENTS else set()
        assert _option12(env) <= own, f"{mac} carries {_option12(env) - own}"


def test_relayed_copies_credit_the_client(envelopes: dict[str, HostEnvelope]) -> None:
    # 2 client broadcasts + 2 relay copies + 2 server replies + 2 relayed replies
    for mac in CLIENTS:
        dhcp = envelopes[mac].pipeline_3.dhcp
        assert len(dhcp) == 8, f"{mac}: {len(dhcp)} DHCP records"


# ── Extractor unit checks on the fixture's packets ───────────────────────────


@pytest.fixture(scope="module")
def records() -> list[dict]:
    return [dhcp_extractor.handle(p, {}) for p in PysharkSource(str(PCAP)).packets()]


def test_chaddr_read_from_current_tshark_dhcp_layer(records: list[dict]) -> None:
    # Wireshark >= 3.0 names the dissector "dhcp"; the old "bootp" layer is gone.
    pkt = next(iter(PysharkSource(str(PCAP)).packets()))
    assert hasattr(pkt, "dhcp") and not hasattr(pkt, "bootp")
    # Every frame, whoever sent it, is filed under its client.
    assert {r["src_mac"].lower() for r in records} == set(CLIENTS)


def test_relayed_and_server_frames_never_carry_sender_ip(records: list[dict]) -> None:
    assert {r["src_ip"] for r in records} == {"0.0.0.0"}  # ciaddr: no lease held yet


def test_fingerprint_only_from_client_messages(records: list[dict]) -> None:
    prl = "1,3,6,12,15,28,42"
    for r in records:
        rf = r["raw_fields"]
        if rf["dhcp_message_type"] in ("discover", "request"):
            assert rf["option55_key_guess"] == prl
        else:  # offer / ack: the server's option list is not the client's PRL
            assert rf["option55_key_guess"] == ""
            assert rf["option60_vendor_class"] == ""


# ── Client identity from DHCP (docs/issues/dhcp-client-identity.md) ──────────


@pytest.mark.xfail(strict=True, reason="leased address (yiaddr) is never recorded")
def test_client_ip_is_its_leased_address(inventory: dict[str, dict]) -> None:
    for mac, (_, leased) in CLIENTS.items():
        assert inventory[mac]["ip_address"] == leased
