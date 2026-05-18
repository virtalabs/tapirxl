from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _slice_ip_tcp_payload, _tcp_payload_hex
from tapirxl.parser.tables import HL7_SENDING_APPS_CANONICAL


def _scrub_segment(seg: str) -> str:
    """Redact PID fields 3/5/7/8 per N3 (PHI-safe)."""
    if not seg.startswith("PID"):
        return seg
    parts = seg.strip().split("|")
    for idx in (3, 5, 7, 8):
        if idx < len(parts):
            parts[idx] = "<PHI>"
    return "|".join(parts)


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "tcp"):
        return None
    raw = _slice_ip_tcp_payload(packet)
    if raw[:1] != b"\x0b":
        raw = _tcp_payload_hex(packet)
    if raw[:1] != b"\x0b":
        return None
    remainder = raw[1:].split(b"\x1c")[0].split(b"\x0d")[0]
    try:
        text = remainder.decode("latin-1", "replace")
    except Exception:
        return None
    u = text.upper()
    idx = u.find("MSH|")
    if idx < 0:
        return None
    text_slice = text[idx:]
    scrubbed_segments = []
    for seg_line in text_slice.split("\r"):
        seg_line_s = seg_line.strip()
        if not seg_line_s:
            continue
        scrubbed_segments.append(_scrub_segment(seg_line_s))
    scrub_join = "\r".join(scrubbed_segments)
    sender = ""
    sender_hint_canon = ""
    if scrubbed_segments and scrubbed_segments[0].startswith("MSH|"):
        flds = scrubbed_segments[0].split("|")
        if len(flds) > 3:
            sender = flds[3][:160]
            for key, canon in HL7_SENDING_APPS_CANONICAL.items():
                if key.upper() in sender.upper():
                    sender_hint_canon = canon
                    break

    rec = _base_record(packet, oui_table, "HL7_MLLP")
    if not rec:
        return None
    rec["raw_fields"] = {
        "segments_preview": scrub_join[:4096],
        "sending_app_raw": sender,
        "sending_facility_normalized_hint": sender_hint_canon,
        "_phi_safe": True,
    }
    return rec
