"""BootstrapFewShot compilation for NormalizeSignal."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_DHCP_MEDICAL_LABELS_SAMPLE = [
    "Philips IntelliVue patient monitor",
    "Philips IntelliVue patient monitor",
    "Philips patient monitoring",
]

_NORM_COMPILE_EXAMPLES = [
    {
        "inputs": {
            "ambiguous_field_bundle": json.dumps(
                {
                    "raw_value": "urn:ihe:pcd:dev:philips-monitor",
                    "source_protocol": "WS_DISCOVERY",
                    "field_path": "ws_types",
                    "candidate_labels": ["IHE PCD patient care device", "OTHER:KEEP_VERBATIM"],
                    "host_context": "aa:aa:aa:aa:aa:aa",
                }
            ),
            "envelope_context": json.dumps({"host_id": "aa", "oui_vendor": "Philips"}),
        },
        "outputs": {"normalized_value": "IHE PCD patient care device", "confidence": "HIGH"},
    },
    {
        "inputs": {
            "ambiguous_field_bundle": json.dumps(
                {
                    "raw_value": "CastFriendlyName=Living Room Speaker",
                    "source_protocol": "MDNS_TXT",
                    "field_path": "mdns_txt_raw",
                    "candidate_labels": ["OTHER:KEEP_VERBATIM"],
                    "host_context": "bb:bb:bb:bb:bb:bb",
                }
            ),
            "envelope_context": "{}",
        },
        "outputs": {"normalized_value": "OTHER:consumer_cast_hint", "confidence": "LOW"},
    },
    {
        "inputs": {
            "ambiguous_field_bundle": json.dumps(
                {
                    "raw_value": "UID: 1.3.46.670589.30.2.222",
                    "source_protocol": "DICOM",
                    "field_path": "dicom_association",
                    "candidate_labels": [
                        "Philips Eleva platform",
                        "Philips Healthcare",
                        "OTHER:KEEP_VERBATIM",
                    ],
                    "host_context": "cc:cc:cc:cc:cc:cc",
                }
            ),
            "envelope_context": json.dumps({"pipeline_3": True}),
        },
        "outputs": {"normalized_value": "Philips Eleva platform", "confidence": "HIGH"},
    },
    {
        "inputs": {
            "ambiguous_field_bundle": json.dumps(
                {
                    "raw_value": "Vendor=SpacelabsHealthcare DHCP",
                    "source_protocol": "DHCP",
                    "field_path": "dhcp.option60",
                    "candidate_labels": [*_DHCP_MEDICAL_LABELS_SAMPLE, "OTHER:KEEP_VERBATIM"],
                    "host_context": "dd:dd:dd:dd:dd:dd",
                }
            ),
            "envelope_context": "{}",
        },
        "outputs": {"normalized_value": "Spacelabs patient monitor", "confidence": "MEDIUM"},
    },
    {
        "inputs": {
            "ambiguous_field_bundle": json.dumps(
                {
                    "raw_value": "SERVER: Linux UPnP/ Sonos",
                    "source_protocol": "SSDP",
                    "field_path": "ssdp.server",
                    "candidate_labels": [
                        "Sonos networked speaker/controller",
                        "Chromecast / cast ecosystem device",
                        "OTHER:KEEP_VERBATIM",
                    ],
                    "host_context": "ee:ee:ee:ee:ee:ee",
                }
            ),
            "envelope_context": "{}",
        },
        "outputs": {
            "normalized_value": "Sonos networked speaker/controller",
            "confidence": "HIGH",
        },
    },
]


def _norm_compile_metric(example, pred, trace=None):
    tgt = str(getattr(example, "normalized_value", "")).strip()
    got = str(getattr(pred, "normalized_value", "")).strip()
    return int(tgt.lower() == got.lower())


def run_compile_normalize(compiled_json: Path) -> None:
    import dspy

    from tapirxl.agent.modules.norm_module import NormModule

    trainset = []
    for ex in _NORM_COMPILE_EXAMPLES:
        trainset.append(
            dspy.Example(**ex["inputs"], **ex["outputs"]).with_inputs(*ex["inputs"].keys())
        )
    module = NormModule()
    optimizer = dspy.BootstrapFewShot(
        metric=_norm_compile_metric, max_bootstrapped_demos=2, max_labeled_demos=4
    )
    compiled = optimizer.compile(module, trainset=trainset)
    compiled.save(str(compiled_json))
    print(f"  compiled NormalizeSignal demos → {compiled_json}", file=sys.stderr)
