"""Unit tests for floor triggers in parser/envelope_builder.py.

Locks each spec §6.2 trigger code in CLAUDE.md against future regressions.
Each test builds a minimal envelope dict by hand (no pyshark dependency) and
calls finalize_envelope_from_records().
"""

from __future__ import annotations

from tapirxl.parser.envelope_builder import (
    finalize_envelope_from_records,
    make_empty_envelope,
)


def _bare_envelope() -> dict:
    return make_empty_envelope("00:09:fb:bd:75:6d", oui_table={})


class TestExistingFloorTriggers:
    """Pre-existing triggers — locked here to detect accidental regressions."""

    def test_medical_uuid_prefix_philips(self) -> None:
        env = _bare_envelope()
        env["ws_vendor_prefix"] = "5048"

        finalize_envelope_from_records(env)

        assert "MEDICAL_UUID_PREFIX" in env["floor_triggers"]

    def test_clinical_service_dicom(self) -> None:
        env = _bare_envelope()
        env["dns_sd_services"] = ["_dicom._tcp.local"]

        finalize_envelope_from_records(env)

        assert "CLINICAL_SERVICE" in env["floor_triggers"]

    def test_expert_anomaly_flag(self) -> None:
        env = _bare_envelope()
        env["expert_flags"] = ["malformed TLS record"]

        finalize_envelope_from_records(env)

        assert "EXPERT_ANOMALY" in env["floor_triggers"]


class TestDicomFloorTriggers:
    def test_dicom_vendor_arc_fires_on_sop_class_hint(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "dicom_association": [
                {
                    "dicom_association": {
                        "sop_class_hints": ["1.3.46.->Philips Healthcare"],
                    }
                }
            ]
        }

        finalize_envelope_from_records(env)

        assert "DICOM_VENDOR_ARC" in env["floor_triggers"]

    def test_dicom_vendor_arc_absent_when_hints_empty(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {"dicom_association": [{"dicom_association": {"sop_class_hints": []}}]}

        finalize_envelope_from_records(env)

        assert "DICOM_VENDOR_ARC" not in env["floor_triggers"]

    def test_philips_image_uid_arc_fires(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "dicom_association": [
                {
                    "dicom_association": {
                        "philips_image_uid_arc_hits": ["1.2.840.113704."],
                    }
                }
            ]
        }

        finalize_envelope_from_records(env)

        assert "DICOM_PHILIPS_IMAGE_UID" in env["floor_triggers"]


class TestDhcpFloorTrigger:
    def test_dhcp_medical_vendor_class_fires(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "dhcp": [{"vendor_medical_hint": "Philips IntelliVue patient monitor"}]
        }

        finalize_envelope_from_records(env)

        assert "DHCP_MEDICAL_VENDOR_CLASS" in env["floor_triggers"]

    def test_dhcp_medical_vendor_class_skips_empty_hint(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {"dhcp": [{"vendor_medical_hint": ""}]}

        finalize_envelope_from_records(env)

        assert "DHCP_MEDICAL_VENDOR_CLASS" not in env["floor_triggers"]


class TestHl7FloorTrigger:
    def test_hl7_clinical_interface_fires(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "hl7_segments": [
                {
                    "segments_preview": "MSH|^~\\&|EPIC|...",
                    "sending_app_raw": "EPIC",
                    "_phi_safe": True,
                }
            ]
        }

        finalize_envelope_from_records(env)

        assert "HL7_CLINICAL_INTERFACE" in env["floor_triggers"]


class TestSnmpFloorTrigger:
    def test_snmp_medical_sysdescr_matches_medical_vendor(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "snmp_sysdescr": [{"sys_descr": "Philips IntelliVue MX700 firmware 1.2.3"}]
        }

        finalize_envelope_from_records(env)

        assert "SNMP_MEDICAL_SYSDESCR" in env["floor_triggers"]

    def test_snmp_medical_sysdescr_skips_non_medical(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {
            "snmp_sysdescr": [{"sys_descr": "Cisco IOS Software, Catalyst Series"}]
        }

        finalize_envelope_from_records(env)

        assert "SNMP_MEDICAL_SYSDESCR" not in env["floor_triggers"]


class TestClinicalAppProtoRemoved:
    """Lock the decision to drop the non-spec CLINICAL_APP_PROTO trigger."""

    def test_pipeline_3_alone_does_not_add_clinical_app_proto(self) -> None:
        env = _bare_envelope()
        env["pipeline_3"] = {"dhcp": [{"vendor_medical_hint": ""}]}

        finalize_envelope_from_records(env)

        assert "CLINICAL_APP_PROTO" not in env["floor_triggers"]
