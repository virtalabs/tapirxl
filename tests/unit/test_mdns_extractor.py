"""Regression tests for issue #39: mDNS / DNS-SD extraction from tshark 'mdns' layers.

tshark dissects UDP/5353 under a dedicated ``mdns`` layer whose fields keep
their ``dns.*`` names, so extractors that only look at ``packet.dns`` never
match. The committed fixture (tests/fixtures/mdns_printer_announcement.pcap)
holds one HP-printer-style mDNS announcement: a service-enumeration PTR, the
service PTR, a multi-string TXT record, an SRV and the A record, all in a
single packet to 224.0.0.251:5353.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from tapirxl.cli import app
from tapirxl.parser.extractors import mdns as mdns_extractor
from tapirxl.schemas.envelope import HostEnvelope

PCAP = Path(__file__).resolve().parents[1] / "fixtures" / "mdns_printer_announcement.pcap"
PRINTER_MAC = "9c:b6:d0:33:00:50"


def _parse_envelopes(pcap: Path) -> list[HostEnvelope]:
    runner = CliRunner()
    result = runner.invoke(app, ["parse", str(pcap)])
    assert result.exit_code == 0, result.output
    return [
        HostEnvelope.model_validate_json(line)
        for line in result.output.splitlines()
        if line.strip().startswith("{")
    ]


def _printer_envelope() -> HostEnvelope:
    for env in _parse_envelopes(PCAP):
        if env.host_id == PRINTER_MAC.lower():
            return env
    raise AssertionError(f"no envelope for printer MAC {PRINTER_MAC}")


class TestMdnsPrinterAnnouncement:
    """Issue #39 acceptance criteria, one mDNS printer announcement."""

    def test_mdns_hostname_taken_from_a_record(self) -> None:
        env = _printer_envelope()
        assert env.pipeline_1 is not None and env.pipeline_1.mdns is not None
        assert env.pipeline_1.mdns.hostname == "NPI300050.local"

    def test_every_txt_string_is_parsed(self) -> None:
        mdns = _printer_envelope().pipeline_1.mdns
        assert mdns is not None
        assert mdns.txt_parsed == {
            "txtvers": "1",
            "ty": "HP LaserJet M507",
            "adminurl": "http://NPI300050.local.",
            "note": "Office 2",
        }

    def test_dns_sd_service_discovered(self) -> None:
        mdns = _printer_envelope().pipeline_1.mdns
        assert mdns is not None
        assert "_ipp._tcp.local" in mdns.dns_sd_services

    def test_mdns_signal_bucket_fires(self) -> None:
        env = _printer_envelope()
        # pipeline_1 is emitted only when an mDNS/DNS-SD block fired.
        assert env.pipeline_1 is not None and env.pipeline_1.mdns is not None
        assert env.triage is not None and env.triage.signal_count >= 1

    def test_inventory_record_hostname_and_port(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["parse", str(PCAP), "--json"])
        assert result.exit_code == 0, result.output
        records = [
            json.loads(line) for line in result.output.splitlines() if line.strip().startswith("{")
        ]
        rec = next(r for r in records if r["mac_address"].lower() == PRINTER_MAC.lower())
        assert rec["hostname"] == "NPI300050.local"
        assert 5353 in rec["open_ports"]


def test_txt_value_with_semicolon_is_kept_intact(monkeypatch) -> None:
    """A valid TXT value may contain ';' — only the capture separator may split it."""
    monkeypatch.setattr(mdns_extractor, "_dns_layer", lambda packet: object())
    monkeypatch.setattr(
        mdns_extractor,
        "_layer_field_values",
        lambda layer, name: ["note=Office 2; floor 3"] if name == "dns_txt" else [],
    )
    monkeypatch.setattr(
        mdns_extractor, "_base_record", lambda packet, oui_table, rec_type: {"type": rec_type}
    )
    rec = mdns_extractor.handle_txt(object(), {})
    assert rec is not None
    assert rec["raw_fields"]["mdns_txt_raw"] == ["note=Office 2; floor 3"]
    assert rec["raw_fields"]["mdns_txt_parsed"] == {"note": "Office 2; floor 3"}
