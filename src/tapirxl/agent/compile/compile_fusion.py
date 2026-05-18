"""BootstrapFewShot compilation for FuseSignals."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import oui_lookup
from tapirxl.core.phi import redact_phi


def _make_empty_base(mac: str) -> dict:
    mac_n = normalize_mac(mac)
    return {
        "host_id": mac_n.lower(), "mac": mac_n, "ip": "", "ip_observations": [],
        "oui_vendor": oui_lookup(mac_n, {}),
        "ws_uuid": None, "ws_vendor_prefix": None, "ws_series_code": None,
        "ws_series_family": None, "ws_types": [], "ws_scopes": [],
        "mdns_hostname": None, "mdns_txt_raw": [], "mdns_txt_parsed": {},
        "dns_sd_services": [], "llmnr_queries": [], "llmnr_hostname": None,
        "ssdp_observations": [], "arp_bindings": [], "capsule_mdip": {},
        "dhcp_hostname": None, "ntlmssp_workstation": None, "ntlmssp_domain": None,
        "ntlmssp_username": None, "ntlmssp_target_computer": None,
        "dicom_modality": None, "dicom_manufacturer": None,
        "dicom_manufacturer_model": None, "expert_flags": [],
        "signal_count": 0, "floor_triggers": [], "contradictions": [],
        "triage": {
            "routing": None, "deterministic_consensus": None,
            "pipelines_fired": [], "contradiction_codes": [],
        },
        "lm_envelope": {"ambiguous_fields": []},
        "pipeline_1": None, "pipeline_2": None, "pipeline_3": None,
    }


def _v2_compiler_envelope(patch: dict) -> str:
    mac = normalize_mac(patch.get("mac") or "")
    base = _make_empty_base(mac)
    base.update(patch)
    return json.dumps(redact_phi(base))


_TRAIN_EXAMPLES = [
    {
        "inputs": {
            "signal_register": _v2_compiler_envelope(
                {
                    "ip": "10.105.14.167",
                    "mac": "00:60:b0:aa:bb:cc",
                    "oui_vendor": "Philips",
                    "ws_uuid": None,
                    "ws_vendor_prefix": None,
                    "ws_series_code": None,
                    "ws_types": [],
                    "ws_scopes": [],
                    "mdns_hostname": None,
                    "mdns_txt_raw": ["Manufacturer=Philips", "Model=Ingenuity Flex"],
                    "mdns_txt_parsed": {"Manufacturer": "Philips", "Model": "Ingenuity Flex"},
                    "dns_sd_services": ["_dicom._tcp.local"],
                    "llmnr_queries": [],
                    "llmnr_hostname": None,
                    "ssdp_observations": [],
                    "arp_bindings": [],
                    "capsule_mdip": {},
                    "contradictions": [],
                    "expert_flags": [],
                    "signal_count": 2,
                    "floor_triggers": ["CLINICAL_SERVICE"],
                    "pipeline_2": None,
                    "pipeline_3": None,
                    "triage": {
                        "routing": "ENQUEUE_FUSION",
                        "deterministic_consensus": {
                            "label": "Philips modality / Ingenuity imaging family cues",
                            "confidence": "HIGH",
                        },
                        "pipelines_fired": ["pipeline_1"],
                        "contradiction_codes": [],
                    },
                    "pipeline_1": {
                        "deterministic_label": "Philips clinical modality (broadcast / SD cues)",
                        "deterministic_confidence": "HIGH",
                        "signals": {"mdns": True, "dicom_dns_sd": True},
                    },
                }
            ),
            "contradiction_flag": "false",
            "contradictions": "",
            "floor_triggers": "CLINICAL_SERVICE",
            "expert_flags": "",
        },
        "outputs": {
            "device_class": "Philips Ingenuity Flex CT scanner",
            "confidence": "HIGH",
        },
    },
    {
        "inputs": {
            "signal_register": _v2_compiler_envelope(
                {
                    "ip": "172.19.80.125",
                    "mac": "00:50:c2:aa:bb:cc",
                    "oui_vendor": "Capsule Tech",
                    "ws_uuid": None,
                    "ws_vendor_prefix": None,
                    "ws_series_code": None,
                    "ws_types": [],
                    "ws_scopes": [],
                    "mdns_hostname": None,
                    "mdns_txt_raw": [],
                    "mdns_txt_parsed": {},
                    "dns_sd_services": [],
                    "llmnr_queries": ["CAPSULE-SERVER"],
                    "llmnr_hostname": None,
                    "ssdp_observations": [],
                    "arp_bindings": [],
                    "capsule_mdip": {},
                    "contradictions": [],
                    "expert_flags": [],
                    "signal_count": 1,
                    "floor_triggers": [],
                    "pipeline_2": None,
                    "pipeline_3": None,
                    "triage": {
                        "routing": "ENQUEUE_FUSION",
                        "deterministic_consensus": {
                            "label": "Patient connectivity middleware (LLMNR CAPSULE-SERVER cue)",
                            "confidence": "MEDIUM",
                        },
                        "pipelines_fired": ["pipeline_1"],
                        "contradiction_codes": [],
                    },
                    "pipeline_1": {
                        "deterministic_label": "Capsule MDIP middleware / bedside gateway cues",
                        "deterministic_confidence": "MEDIUM",
                        "signals": {"llmnr": True},
                    },
                }
            ),
            "contradiction_flag": "false",
            "contradictions": "",
            "floor_triggers": "",
            "expert_flags": "",
        },
        "outputs": {
            "device_class": "Capsule MDIP middleware server",
            "confidence": "MEDIUM",
        },
    },
    {
        "inputs": {
            "signal_register": _v2_compiler_envelope(
                {
                    "ip": "10.105.15.245",
                    "mac": "00:00:00:aa:bb:cc",
                    "oui_vendor": "UNKNOWN",
                    "ws_uuid": None,
                    "ws_vendor_prefix": None,
                    "ws_series_code": None,
                    "ws_types": [],
                    "ws_scopes": [],
                    "mdns_hostname": None,
                    "mdns_txt_raw": [],
                    "mdns_txt_parsed": {},
                    "dns_sd_services": ["_dicom._tcp.local", "_hl7._tcp.local"],
                    "llmnr_queries": [],
                    "llmnr_hostname": None,
                    "ssdp_observations": [],
                    "arp_bindings": [],
                    "capsule_mdip": {},
                    "contradictions": [],
                    "expert_flags": [],
                    "signal_count": 2,
                    "floor_triggers": ["CLINICAL_SERVICE"],
                    "pipeline_2": None,
                    "pipeline_3": None,
                    "triage": {
                        "routing": "ENQUEUE_FUSION",
                        "deterministic_consensus": None,
                        "pipelines_fired": ["pipeline_1"],
                        "contradiction_codes": [],
                    },
                    "pipeline_1": {
                        "deterministic_label": "Clinical application services advertised (DNS-SD)",
                        "deterministic_confidence": "HIGH",
                        "signals": {"dns_sd_services": ["_dicom._tcp.local", "_hl7._tcp.local"]},
                    },
                }
            ),
            "contradiction_flag": "false",
            "contradictions": "",
            "floor_triggers": "CLINICAL_SERVICE",
            "expert_flags": "",
        },
        "outputs": {
            "device_class": "DICOM archive / HL7 interface node",
            "confidence": "MEDIUM",
        },
    },
    {
        "inputs": {
            "signal_register": _v2_compiler_envelope(
                {
                    "ip": "172.19.84.96",
                    "mac": "00:50:56:8b:12:34",
                    "oui_vendor": "VMware",
                    "ws_uuid": None,
                    "ws_vendor_prefix": None,
                    "ws_series_code": None,
                    "ws_types": [],
                    "ws_scopes": [],
                    "mdns_hostname": None,
                    "mdns_txt_raw": [],
                    "mdns_txt_parsed": {},
                    "dns_sd_services": [],
                    "llmnr_queries": [],
                    "llmnr_hostname": None,
                    "ssdp_observations": [],
                    "arp_bindings": [],
                    "capsule_mdip": {},
                    "contradictions": [],
                    "expert_flags": [],
                    "signal_count": 1,
                    "floor_triggers": [],
                    "pipeline_2": None,
                    "pipeline_3": None,
                    "triage": {
                        "routing": "ENQUEUE_FUSION",
                        "deterministic_consensus": {
                            "label": "Hypervisor-hosted guest NIC (VMware OUI)",
                            "confidence": "MEDIUM",
                        },
                        "pipelines_fired": ["pipeline_1"],
                        "contradiction_codes": [],
                    },
                    "pipeline_1": {
                        "deterministic_label": "Virtualization guest NIC (minimal L2 broadcasts)",
                        "deterministic_confidence": "LOW",
                        "signals": {"oui_hypervisor": "VMware"},
                    },
                }
            ),
            "contradiction_flag": "false",
            "contradictions": "",
            "floor_triggers": "",
            "expert_flags": "",
        },
        "outputs": {
            "device_class": "Clinical workstation (VMware VM)",
            "confidence": "LOW",
        },
    },
]


def _compile_metric(example, pred, trace=None):
    conf_ok = int(
        str(getattr(example, "confidence", "")).strip().upper()
        == str(getattr(pred, "confidence", "")).strip().upper()
    )
    expected_class = str(getattr(example, "device_class", "")).lower()
    predicted_class = str(getattr(pred, "device_class", "")).lower()
    class_ok = int(
        expected_class in predicted_class
        or any(w in predicted_class for w in expected_class.split()[:2])
    )
    return conf_ok + class_ok


def run_compile(compiled_json: Path) -> None:
    import dspy

    from tapirxl.agent.modules.fuse_module import FuseModule

    trainset = []
    for ex in _TRAIN_EXAMPLES:
        trainset.append(
            dspy.Example(**ex["inputs"], **ex["outputs"]).with_inputs(*ex["inputs"].keys())
        )
    module = FuseModule()
    optimizer = dspy.BootstrapFewShot(
        metric=_compile_metric,
        max_bootstrapped_demos=2,
        max_labeled_demos=4,
    )
    compiled = optimizer.compile(module, trainset=trainset)
    compiled.save(str(compiled_json))
    print(f"  compiled module saved → {compiled_json}", file=sys.stderr)
