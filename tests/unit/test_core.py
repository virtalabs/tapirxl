"""Unit tests for src/tapirxl/core/ and src/tapirxl/schemas/."""

from __future__ import annotations

from pathlib import Path

from tapirxl.core.enums import (
    CPE_VENDOR_ENUM,
    enum_or_none,
    to_cpe_vendor,
    to_device_class,
)
from tapirxl.core.ip import ip_sort_key
from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import load_oui_table, oui_lookup
from tapirxl.core.phi import redact_phi, scrub_hl7_pid_segment
from tapirxl.schemas.envelope import HostEnvelope, SignalObservation
from tapirxl.schemas.fusion import FusionOutput
from tapirxl.schemas.inventory import InventoryRecord

# ── core/mac ──────────────────────────────────────────────────────────────────


class TestNormalizeMac:
    def test_hyphen_separated(self):
        assert normalize_mac("00-09-fb-bd-75-6d") == "00:09:FB:BD:75:6D"

    def test_already_normalized(self):
        assert normalize_mac("00:09:FB:BD:75:6D") == "00:09:FB:BD:75:6D"

    def test_lowercase(self):
        assert normalize_mac("00:09:fb:bd:75:6d") == "00:09:FB:BD:75:6D"

    def test_empty(self):
        assert normalize_mac("") == ""

    def test_zero_padding(self):
        assert normalize_mac("0:9:f:b:7:6") == "00:09:0F:0B:07:06"


# ── core/oui ──────────────────────────────────────────────────────────────────


class TestOuiLookup:
    def setup_method(self):
        self.table = load_oui_table(Path("/dev/null"))

    def test_known_philips(self):
        assert self.table.get("00:09:FB") == "Philips Patient Monitoring"

    def test_unknown_returns_unknown(self):
        assert oui_lookup("AA:BB:CC:DD:EE:FF", self.table) == "UNKNOWN"

    def test_empty_mac(self):
        assert oui_lookup("", self.table) == "UNKNOWN"

    def test_fallback_vmware(self):
        assert "VMware" in oui_lookup("00:50:56:AA:BB:CC", self.table)

    def test_fallback_draeger(self):
        result = oui_lookup("00:10:5D:AA:BB:CC", self.table)
        assert "Draeger" in result or "draeger" in result.lower()


# ── core/phi ──────────────────────────────────────────────────────────────────


class TestRedactPhi:
    def test_dicom_0010_key_removed(self):
        assert redact_phi({"0010,0010": "PatientName"}) == {}

    def test_non_phi_key_kept(self):
        result = redact_phi({"host_id": "abc", "0010,0020": "MRN"})
        assert result == {"host_id": "abc"}

    def test_nested_dict(self):
        obj = {"tags": {"0010,0010": "name", "0008,0070": "Philips"}}
        result = redact_phi(obj)
        assert result == {"tags": {"0008,0070": "Philips"}}

    def test_list_recursive(self):
        result = redact_phi([{"0010,0010": "x"}, {"other": "y"}])
        assert result == [{}, {"other": "y"}]

    def test_pid_segment_string(self):
        pid = "PID|1||MRN123|PatientName|19800101||M|"
        result = redact_phi(pid)
        assert "<PHI>" in result
        assert "MRN123" not in result

    def test_non_pid_string_unchanged(self):
        assert redact_phi("some random text") == "some random text"


class TestScrubHl7PidSegment:
    def test_pid_fields_redacted(self):
        seg = "PID|1||MRN123|Smith^John|19800101||M|"
        result = scrub_hl7_pid_segment(seg)
        assert result.split("|")[3] == "<PHI>"  # field 3
        assert result.split("|")[5] == "<PHI>"  # field 5

    def test_non_pid_unchanged(self):
        seg = "MSH|^~\\&|EPIC|HOSPITAL|RIS|HOSPITAL|20230101||ORM^O01|1|P|2.3"
        assert scrub_hl7_pid_segment(seg) == seg


# ── core/ip ───────────────────────────────────────────────────────────────────


class TestIpSortKey:
    def test_valid_ipv4(self):
        assert ip_sort_key("10.10.10.21") == (10, 10, 10, 21)

    def test_invalid_returns_sentinel(self):
        assert ip_sort_key("bad") == (999, 999, 999, 999)

    def test_sort_ordering(self):
        ips = ["10.10.10.30", "10.10.10.21", "10.10.20.1"]
        assert sorted(ips, key=ip_sort_key) == ["10.10.10.21", "10.10.10.30", "10.10.20.1"]


# ── core/enums ────────────────────────────────────────────────────────────────


class TestEnumOrNone:
    def test_valid_value(self):
        assert enum_or_none("philips", CPE_VENDOR_ENUM) == "philips"

    def test_invalid_value(self):
        assert enum_or_none("unknown_vendor", CPE_VENDOR_ENUM) is None

    def test_none_input(self):
        assert enum_or_none(None, CPE_VENDOR_ENUM) is None

    def test_empty_string(self):
        assert enum_or_none("", CPE_VENDOR_ENUM) is None


class TestToCpeVendor:
    def test_dicom_philips_uid(self):
        env = {
            "pipeline_3": {
                "dicom_association": [{"implementation_class_uid": "1.3.46.670589.30.36.0"}]
            }
        }
        assert to_cpe_vendor(env) == "philips"

    def test_dhcp_msft(self):
        env = {"pipeline_3": {"dhcp": [{"option60_vendor_class": "MSFT 5.0"}]}}
        assert to_cpe_vendor(env) == "microsoft"

    def test_oui_vmware(self):
        env = {"oui_vendor": "VMware, Inc."}
        assert to_cpe_vendor(env) == "vmware"

    def test_no_signal(self):
        env = {"oui_vendor": "UNKNOWN"}
        assert to_cpe_vendor(env) is None


class TestToDeviceClass:
    def test_dicom_modality_ct(self):
        env = {"pipeline_3": {"dicom_association": [{"dicom_modality": "CT"}]}}
        assert to_device_class(env) == "CT"

    def test_ws_discovery_patient_monitor(self):
        env = {"ws_series_code": "BH"}
        assert to_device_class(env) == "patient_monitor"

    def test_palo_alto_firewall(self):
        env = {"oui_vendor": "Palo Alto Networks"}
        assert to_device_class(env) == "firewall"


# ── schemas/envelope ──────────────────────────────────────────────────────────


class TestHostEnvelope:
    def test_pipeline_blocks_absent_by_default(self):
        env = HostEnvelope(host_id="aa:bb:cc:dd:ee:ff")
        assert env.pipeline_1 is None
        assert env.pipeline_2 is None
        assert env.pipeline_3 is None

    def test_extra_fields_allowed(self):
        env = HostEnvelope(host_id="aa:bb:cc:dd:ee:ff", legacy_flat_key="value")
        assert env.model_extra.get("legacy_flat_key") == "value"

    def test_model_dump_roundtrip(self):
        env = HostEnvelope(host_id="aa:bb:cc:dd:ee:ff", oui_vendor="Philips")
        data = env.model_dump()
        env2 = HostEnvelope(**data)
        assert env2.host_id == env.host_id


class TestSignalObservation:
    def test_minimal_construction(self):
        sig = SignalObservation(
            pipeline=1, protocol="WS_DISCOVERY", src_mac="00:09:fb:bd:75:6d", timestamp=1000.0
        )
        assert sig.expert_flag is False
        assert sig.fields == {}


# ── schemas/inventory ─────────────────────────────────────────────────────────


class TestInventoryRecord:
    def test_required_fields(self):
        rec = InventoryRecord(ip_address="10.0.0.1", mac_address="AA:BB:CC:DD:EE:FF", open_ports=[])
        assert rec.hostname is None
        assert rec.vendor is None

    def test_valid_vendor(self):
        rec = InventoryRecord(
            ip_address="10.0.0.1", mac_address="AA:BB:CC:DD:EE:FF", open_ports=[], vendor="philips"
        )
        assert rec.vendor == "philips"


# ── schemas/fusion ────────────────────────────────────────────────────────────


class TestFusionOutput:
    def test_construction(self):
        fuse = FusionOutput(
            host_id="aa:bb:cc:dd:ee:ff",
            mac="AA:BB:CC:DD:EE:FF",
            ip="10.0.0.1",
            path="FUSED",
            device_class="CT",
            confidence="HIGH",
            reasoning_trace="DICOM modality CT confirmed",
        )
        assert fuse.contradiction is False
        assert fuse.open_questions == []

    def test_contradiction_flag(self):
        fuse = FusionOutput(
            host_id="aa:bb:cc:dd:ee:ff",
            mac="AA:BB:CC:DD:EE:FF",
            ip="10.0.0.1",
            path="FUSED",
            device_class=None,
            confidence="MEDIUM",
            reasoning_trace="contradiction detected",
            contradiction=True,
            contradictions=["C1 OUI_DICOM_VENDOR_MISMATCH"],
        )
        assert fuse.contradiction is True
        assert "C1" in fuse.contradictions[0]
