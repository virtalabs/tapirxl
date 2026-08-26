"""Unit tests for core/inventory_record.build_jsonl_record().

Locks the 9-key shape and every enum constraint from
schemas/inventory_record.schema.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tapirxl.core.inventory_record import build_jsonl_record
from tapirxl.parser.envelope_builder import make_empty_envelope

SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "inventory_record.schema.json"

# 9 required keys per schema.
_SCHEMA_KEYS: frozenset[str] = frozenset(
    {
        "hostname",
        "ip_address",
        "mac_address",
        "vendor",
        "product",
        "version",
        "device_class",
        "open_ports",
        "confidence",
    }
)


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _enum_for(schema: dict, prop: str) -> set:
    return set(schema["properties"][prop]["enum"])


def _bare_envelope() -> dict:
    return make_empty_envelope("00:09:fb:bd:75:6d", oui_table={})


class TestBuildJsonlRecordShape:
    """Lock the 9-key shape against future drift."""

    def test_returns_exactly_nine_keys(self) -> None:
        rec = build_jsonl_record(_bare_envelope(), fused=None, no_llm=True)
        assert set(rec.keys()) == _SCHEMA_KEYS

    def test_bare_envelope_has_string_addresses(self) -> None:
        rec = build_jsonl_record(_bare_envelope(), fused=None, no_llm=True)
        assert isinstance(rec["ip_address"], str)
        assert isinstance(rec["mac_address"], str)
        assert rec["mac_address"] == "00:09:FB:BD:75:6D"

    def test_bare_envelope_open_ports_is_empty_list(self) -> None:
        rec = build_jsonl_record(_bare_envelope(), fused=None, no_llm=True)
        assert rec["open_ports"] == []
        assert isinstance(rec["open_ports"], list)

    def test_bare_envelope_optionals_are_null(self) -> None:
        rec = build_jsonl_record(_bare_envelope(), fused=None, no_llm=True)
        assert rec["hostname"] is None
        assert rec["vendor"] is None
        assert rec["product"] is None
        assert rec["version"] is None
        assert rec["device_class"] is None


class TestEnumConstraints:
    """Every enum-valued field must satisfy the schema enum."""

    def test_vendor_constraint(self, schema: dict) -> None:
        allowed = _enum_for(schema, "vendor")
        env = _bare_envelope()
        env["pipeline_3"] = {"dicom_association": [{"dicom_manufacturer": "Philips Healthcare"}]}
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["vendor"] in allowed
        assert rec["vendor"] == "philips"

    def test_product_constraint(self, schema: dict) -> None:
        allowed = _enum_for(schema, "product")
        env = _bare_envelope()
        env["pipeline_3"] = {
            "dicom_association": [{"implementation_class_uid": "1.3.46.670589.30.36.0"}]
        }
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["product"] in allowed
        assert rec["product"] == "brilliance_ict"

    def test_device_class_dicom_modality(self, schema: dict) -> None:
        allowed = _enum_for(schema, "device_class")
        env = _bare_envelope()
        env["pipeline_3"] = {"dicom_association": [{"dicom_modality": "CT"}]}
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["device_class"] in allowed
        assert rec["device_class"] == "CT"

    def test_device_class_patient_monitor_from_ws_series(self, schema: dict) -> None:
        allowed = _enum_for(schema, "device_class")
        env = _bare_envelope()
        env["ws_series_code"] = "BH"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["device_class"] in allowed
        assert rec["device_class"] == "patient_monitor"

    def test_confidence_constraint_low(self, schema: dict) -> None:
        allowed = _enum_for(schema, "confidence")
        env = _bare_envelope()
        env["signal_count"] = 1
        env["floor_triggers"] = []
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["confidence"] in allowed
        assert rec["confidence"] == "LOW"

    def test_confidence_triage_only_maps_to_low(self) -> None:
        """build_jsonl_record collapses TRIAGE_ONLY → LOW for schema fitness."""
        env = _bare_envelope()
        env["signal_count"] = 3
        env["floor_triggers"] = ["MEDICAL_UUID_PREFIX"]
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["confidence"] == "LOW"


class TestSonositeInventoryMapping:
    def test_sonosite_vendor_product_and_us_modality(self, schema: dict) -> None:
        allowed_vendor = _enum_for(schema, "vendor")
        allowed_product = _enum_for(schema, "product")
        allowed_device = _enum_for(schema, "device_class")

        env = make_empty_envelope("00:08:fb:34:01:9a", oui_table={"00:08:FB": "SonoSite Inc."})
        env["pipeline_3"] = {
            "dicom_association": [
                {
                    "dicom_association": {
                        "implementation_class_uid": "1.2.840.114340.3",
                        "implementation_version_name": "Tiller_SV1000",
                        "sop_class_uids_observed": ["1.2.840.10008.5.1.4.1.1.6.1"],
                        "dicom_modality": "US",
                        "dicom_manufacturer": "SonoSite",
                    }
                }
            ]
        }

        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["vendor"] in allowed_vendor
        assert rec["product"] in allowed_product
        assert rec["device_class"] in allowed_device
        assert rec["vendor"] == "sonosite"
        assert rec["product"] == "edge_ii"
        assert rec["device_class"] == "US"

    def test_us_modality_from_sop_class_uid_fallback(self, schema: dict) -> None:
        allowed_device = _enum_for(schema, "device_class")
        env = _bare_envelope()
        env["pipeline_3"] = {
            "dicom_association": [
                {
                    "dicom_association": {
                        "sop_class_uids_observed": ["1.2.840.10008.5.1.4.1.1.3.1"],
                    }
                }
            ]
        }
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["device_class"] in allowed_device
        assert rec["device_class"] == "US"


class TestOpenPortsDerivation:
    def test_ws_discovery_adds_3702(self) -> None:
        env = _bare_envelope()
        env["ws_uuid"] = "5048bh-1234-5678-9abc-def012345678"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert 3702 in rec["open_ports"]

    def test_mdns_adds_5353(self) -> None:
        env = _bare_envelope()
        env["mdns_hostname"] = "philips-mx700.local"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert 5353 in rec["open_ports"]

    def test_dns_sd_dicom_adds_104(self) -> None:
        env = _bare_envelope()
        env["dns_sd_services"] = ["_dicom._tcp.local"]
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert 104 in rec["open_ports"]

    def test_open_ports_are_sorted_and_unique(self) -> None:
        env = _bare_envelope()
        env["ws_uuid"] = "abc"
        env["mdns_hostname"] = "x"
        env["dns_sd_services"] = ["_dicom._tcp.local", "_dicom._tcp.local"]
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        ports = rec["open_ports"]
        assert ports == sorted(set(ports))
        assert all(0 <= p <= 65535 for p in ports)


class TestHostnameDerivation:
    def test_dhcp_hostname_priority(self) -> None:
        env = _bare_envelope()
        env["dhcp_hostname"] = "via-dhcp"
        env["mdns_hostname"] = "via-mdns"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["hostname"] == "via-dhcp"

    def test_mdns_fallback(self) -> None:
        env = _bare_envelope()
        env["mdns_hostname"] = "only-mdns.local"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["hostname"] == "only-mdns.local"

    def test_dicom_ae_calling_fallback(self) -> None:
        env = _bare_envelope()
        env["dicom_ae_calling"] = "SONOSITE"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["hostname"] == "SONOSITE"

    def test_dicom_ae_calling_does_not_override_dhcp(self) -> None:
        env = _bare_envelope()
        env["dhcp_hostname"] = "via-dhcp"
        env["dicom_ae_calling"] = "SONOSITE"
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["hostname"] == "via-dhcp"


class TestVersionDerivation:
    def test_dicom_software_versions(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {"dicom_association": [{"dicom_software_versions": "Eleva 4.5.1"}]}
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["version"] == "Eleva 4.5.1"

    def test_dicom_software_versions_nested(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "dicom_association": [{"dicom_association": {"dicom_software_versions": "4.1.6"}}]
        }
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["version"] == "4.1.6"

    def test_mdns_txt_firmware_key(self) -> None:
        env = _bare_envelope()
        env["mdns_txt_parsed"] = {"firmware": "1.2.3"}
        rec = build_jsonl_record(env, fused=None, no_llm=True)
        assert rec["version"] == "1.2.3"


class TestDeterministicConfidencePropagation:
    """Deterministic routing must carry confidence even with no_llm=True.

    Regression guard for the `not no_llm` gate that previously suppressed
    DETERMINISTIC_FINAL consensus on the `tapirxl parse --json` path.
    """

    def test_effective_inventory_conf_deterministic_final_returns_high(self) -> None:
        from tapirxl.core.inventory_record import _effective_inventory_conf

        row = {
            "triage": {
                "routing": "DETERMINISTIC_FINAL",
                "deterministic_consensus": {
                    "label": "Philips IntelliVue MX700",
                    "confidence": "HIGH",
                },
            },
        }
        assert _effective_inventory_conf(row, fused=None, no_llm=True) == "HIGH"

    def test_effective_inventory_conf_stamp_low_returns_low(self) -> None:
        from tapirxl.core.inventory_record import _effective_inventory_conf

        row = {"triage": {"routing": "STAMP_LOW"}}
        assert _effective_inventory_conf(row, fused=None, no_llm=True) == "LOW"
