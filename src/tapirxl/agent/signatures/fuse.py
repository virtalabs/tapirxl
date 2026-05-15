"""FuseSignals DSPy signatures — do NOT rename fields (ABI break for compiled modules)."""
from __future__ import annotations

import dspy


class ContradictSignals(dspy.Signature):
    """Detect conflicting device identity signals across broadcast protocols for one network host.

    Compare signals pairwise: WS-Discovery UUID vendor vs OUI vendor, mDNS hostname vs
    ws_vendor_prefix device class, dns_sd_services type vs mdns_txt_parsed vendor field,
    llmnr_hostname vs mdns_hostname. Flag conflicts that imply different device classes.
    """

    signal_register: str = dspy.InputField(
        desc="JSON-encoded signal register row for this host (all broadcast protocol fields)"
    )
    contradiction_flag: str = dspy.OutputField(
        desc="'true' if any signal conflict found implying different device classes, else 'false'"
    )
    contradictions: str = dspy.OutputField(
        desc="Pipe-separated descriptions of each conflict found. Empty string if none."
    )


class FuseSignals(dspy.Signature):
    """Classify a medical network device using the v2.0 stacked pipeline envelope JSON.

    Confidence rules:
    HIGH:   3+ independent signals agree AND contradiction_flag is false
            OR 2+ signals agree AND floor_trigger present AND contradiction_flag is false
    MEDIUM: 2 signals present, OR 1 signal with floor_trigger,
            OR contradiction_flag=true caps confidence at MEDIUM regardless of signal_count
    LOW:    1 signal, no floor trigger (edge cases reaching fusion)
    """

    signal_register: str = dspy.InputField(
        desc="PHI-redacted v2 envelope JSON (per-MAC) with pipeline_*/triage/lm_ambiguous payloads"
    )
    contradiction_flag: str = dspy.InputField(desc="'true' if signal conflicts were detected")
    contradictions: str = dspy.InputField(
        desc="Pipe-separated contradiction descriptions or empty"
    )
    floor_triggers: str = dspy.InputField(
        desc="Pipe-separated triggers: MEDICAL_UUID_PREFIX | CLINICAL_SERVICE | EXPERT_ANOMALY | …"
    )
    expert_flags: str = dspy.InputField(
        desc="Pipe-separated expert anomaly messages or empty"
    )
    device_class: str = dspy.OutputField(
        desc=(
            "Human-readable device classification. "
            "Examples: 'Philips IntelliVue MX700/800 monitor', "
            "'DICOM archive node', 'Capsule MDIP middleware server', 'Clinical imaging workstation'"
        )
    )
    confidence: str = dspy.OutputField(desc="Exactly one of: HIGH, MEDIUM, LOW")
    reasoning_trace: str = dspy.OutputField(
        desc="Full chain-of-thought reasoning explaining how signals led to the classification"
    )
    open_questions: str = dspy.OutputField(
        desc="Pipe-separated signals that would upgrade confidence if obtained. Empty if none."
    )


class FuseSignalsRLM(dspy.Signature):
    """Classify a medical network device via RLM programmatic exploration against v2.0 envelopes."""

    signal_register: str = dspy.InputField(
        desc="PHI-redacted stacked-pipeline envelope JSON for this host"
    )
    floor_triggers: str = dspy.InputField(
        desc="Pipe-separated floor triggers (see FuseSignals for vocabulary)"
    )
    expert_flags: str = dspy.InputField(
        desc="Pipe-separated expert anomaly messages or empty"
    )
    device_class: str = dspy.OutputField(
        desc="Human-readable device classification"
    )
    confidence: str = dspy.OutputField(desc="Exactly one of: HIGH, MEDIUM, LOW")
    reasoning_trace: str = dspy.OutputField(
        desc="Full chain-of-thought reasoning explaining how signals led to the classification"
    )
    open_questions: str = dspy.OutputField(
        desc="Pipe-separated signals that would upgrade confidence if obtained. Empty if none."
    )
    contradiction_flag: str = dspy.OutputField(
        desc="'true' if any signal conflict found implying different device classes, else 'false'"
    )
    contradictions: str = dspy.OutputField(
        desc="Pipe-separated descriptions of each conflict found. Empty string if none."
    )
