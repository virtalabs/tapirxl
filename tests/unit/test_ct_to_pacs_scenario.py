"""Smoke tests for the minimal ct_to_pacs_scenario manifest and PCAP."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scapy.utils import rdpcap
from typer.testing import CliRunner

from tapirxl.cli import app
from tapirxl.fixtures.generator import generate_packets
from tapirxl.fixtures.loader import load_signal_manifest
from tapirxl.schemas.envelope import HostEnvelope

MANIFEST = (
    Path(__file__).resolve().parents[2] / "src/tapirxl/fixtures/ct_to_pacs_scenario.toml"
)
PCAP = Path(__file__).resolve().parents[1] / "fixtures/ct_to_pacs_scenario.pcap"

GE_CT_MAC = "00:10:18:aa:bb:01"
PACS_MAC = "00:1a:2b:3c:51:10"


def _parse_envelopes(pcap: Path) -> list[HostEnvelope]:
    runner = CliRunner()
    result = runner.invoke(app, ["parse", str(pcap)])
    assert result.exit_code == 0, result.output
    envelopes: list[HostEnvelope] = []
    for line in result.output.splitlines():
        line = line.strip()
        if line.startswith("{"):
            envelopes.append(HostEnvelope.model_validate_json(line))
    return envelopes


def _parse_inventory(pcap: Path) -> list[dict]:
    runner = CliRunner()
    result = runner.invoke(app, ["parse", str(pcap), "--json"])
    assert result.exit_code == 0, result.output
    return [
        json.loads(line)
        for line in result.output.splitlines()
        if line.strip().startswith("{")
    ]


def _host_by_id(envelopes: list[HostEnvelope], mac: str) -> HostEnvelope:
    for env in envelopes:
        if env.host_id == mac:
            return env
    raise AssertionError(f"no envelope for host_id {mac!r}")


def test_manifest_loads() -> None:
    m = load_signal_manifest(MANIFEST)
    assert m.meta.manifest_id == "ct_to_pacs_v1"
    assert len(m.assets) == 4
    assert len(m.flows) == 1
    assert m.flows[0].type == "dicom_associate_and_cstore"
    assert "intellivue_mp5" not in m.assets
    ge = m.assets["ge_brightspeed_ct"]
    assert ge.cpe.startswith("cpe:2.3:h:gehealthcare:brightspeed_elite_select")
    assert ge.emits == ["llmnr_response"]
    pacs = m.assets["rad_pacs_001"]
    assert pacs.ip == "10.40.2.10"
    assert pacs.mac == "00:1a:2b:3c:51:10"
    assert pacs.hostname == "PACS-CENTRICITY-001"


def test_generate_packets_non_empty() -> None:
    m = load_signal_manifest(MANIFEST)
    pkts = generate_packets(m)
    assert len(pkts) >= 10


def test_pcap_exists_and_has_expected_packet_count() -> None:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    pkts = rdpcap(str(PCAP))
    assert len(pkts) == 19


def test_ge_ct_dicom_assoc_rq_and_cstore_modality() -> None:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    env = _host_by_id(_parse_envelopes(PCAP), GE_CT_MAC)
    assert env.pipeline_3 is not None
    assoc = env.pipeline_3.dicom_association or []
    pdu_types = {a.pdu_type_byte for a in assoc if a.pdu_type_byte}
    assert "01" in pdu_types
    assert "04" in pdu_types
    modalities = [a.tags.modality for a in assoc if a.tags and a.tags.modality]
    assert "CT" in modalities
    impl_uids = [a.implementation_class_uid for a in assoc if a.implementation_class_uid]
    assert "1.2.840.113619.2.5" in impl_uids


def test_pacs_dicom_assoc_ac_impl_uid() -> None:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    env = _host_by_id(_parse_envelopes(PCAP), PACS_MAC)
    assert env.pipeline_3 is not None
    assoc = env.pipeline_3.dicom_association or []
    ac = [a for a in assoc if a.pdu_type_byte == "02"]
    assert ac, "expected A-ASSOC-AC on PACS host"
    assert ac[0].implementation_class_uid == "1.2.840.113619.7.5.1"


def test_inventory_emits_exactly_two_clinical_assets() -> None:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    records = _parse_inventory(PCAP)
    assert len(records) == 2
    macs = {r["mac_address"].lower() for r in records}
    assert macs == {GE_CT_MAC, PACS_MAC}


def test_ge_ct_inventory_fields() -> None:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    ge = next(r for r in _parse_inventory(PCAP) if r["mac_address"].lower() == GE_CT_MAC)
    assert ge["hostname"] == "BRIGHTSPEED01"
    assert ge["vendor"] == "gehealthcare"
    assert ge["product"] == "brightspeed_elite_select"
    assert ge["device_class"] == "CT"
    assert ge["confidence"] in {"MEDIUM", "HIGH"}


def test_pacs_inventory_fields() -> None:
    if not PCAP.exists():
        pytest.skip(f"PCAP not found: {PCAP}")
    pacs = next(r for r in _parse_inventory(PCAP) if r["mac_address"].lower() == PACS_MAC)
    assert pacs["ip_address"] == "10.40.2.10"
    assert pacs["vendor"] == "gehealthcare"
    assert pacs["product"] == "centricity_pacs_iw"
    assert pacs["device_class"] == "pacs"
