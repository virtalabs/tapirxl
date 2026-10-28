"""DHCP through a relay agent (tests/fixtures/dhcp_relay_scenario.pcap).

Two clients on two VLANs get leases through one router-on-a-stick relay; the
capture sees each client message twice (client broadcast, relay copy) and each
server reply twice (server -> relay, relay -> client). See the builder,
tests/fixtures/build_dhcp_relay_scenario.py, for the frame layout.

The xfail tests describe the correct behaviour and are strict: when a fix
lands they XPASS and fail the run, so the marker must come off with the fix.
  - docs/issues/dhcp-relay-attribution.md  (DHCP records keyed by chaddr)
  - docs/issues/dhcp-client-identity.md    (option 53, yiaddr, hostname choice)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tapirxl.cli import app
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


@pytest.mark.xfail(strict=True, reason="relayed DHCP keyed by Ethernet source, not chaddr")
def test_relay_router_gets_no_client_hostname(inventory: dict[str, dict]) -> None:
    router = inventory.get(ROUTER_MAC)
    assert router is None or router["hostname"] is None


@pytest.mark.xfail(strict=True, reason="relayed DHCP keyed by Ethernet source, not chaddr")
def test_no_host_carries_another_hosts_option12(envelopes: dict[str, HostEnvelope]) -> None:
    for mac, env in envelopes.items():
        own = {CLIENTS[mac][0]} if mac in CLIENTS else set()
        assert _option12(env) <= own, f"{mac} carries {_option12(env) - own}"


@pytest.mark.xfail(strict=True, reason="relayed DHCP keyed by Ethernet source, not chaddr")
def test_relayed_copies_credit_the_client(envelopes: dict[str, HostEnvelope]) -> None:
    # 2 client broadcasts + 2 relay copies + 2 server replies + 2 relayed replies
    for mac in CLIENTS:
        dhcp = envelopes[mac].pipeline_3.dhcp
        assert len(dhcp) == 8, f"{mac}: {len(dhcp)} DHCP records"


# ── Client identity from DHCP (docs/issues/dhcp-client-identity.md) ──────────


@pytest.mark.xfail(strict=True, reason="leased address (yiaddr) is never recorded")
def test_client_ip_is_its_leased_address(inventory: dict[str, dict]) -> None:
    for mac, (_, leased) in CLIENTS.items():
        assert inventory[mac]["ip_address"] == leased
