"""PHI redaction — no project imports.

Mandatory before writing any patient-adjacent data to the HostEnvelope or
passing it to an LM call. See ARCHITECTURE.md §4.4.3 and invariant N5.
"""

from __future__ import annotations

import re


def redact_phi(obj: object) -> object:
    """Strip HIPAA-sensitive DICOM Patient group tags and HL7 PID fields."""
    if isinstance(obj, dict):
        out: dict = {}
        for k, v in obj.items():
            key_s = str(k)
            if key_s.lower().startswith("0010"):
                continue
            out[key_s] = redact_phi(v)
        return out
    if isinstance(obj, list):
        return [redact_phi(x) for x in obj]
    if isinstance(obj, str):
        s = re.sub(
            r"\(0010,\s?[0-9a-fA-F]{4}\)",
            "(0010,<PHI>)",
            obj,
            flags=re.IGNORECASE,
        )
        if "|" in s and s.startswith("PID|"):
            parts = s.strip().split("|")
            for idx in (3, 5, 7, 8):
                if idx < len(parts):
                    parts[idx] = "<PHI>"
            return "|".join(parts)
        return s
    return obj


def scrub_hl7_pid_segment(seg: str) -> str:
    """Redact PID-3/5/7/8 fields in an HL7 PID segment string."""
    if not seg.startswith("PID"):
        return seg
    parts = seg.strip().split("|")
    for idx in (3, 5, 7, 8):
        if idx < len(parts):
            parts[idx] = "<PHI>"
    return "|".join(parts)
