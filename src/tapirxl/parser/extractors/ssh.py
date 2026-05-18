from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe, _tcp_payload_hex


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "tcp"):
        return None
    dport = str(_safe(packet.tcp, "dstport", "") or "")
    sport = str(_safe(packet.tcp, "srcport", "") or "")
    if dport != "22" and sport != "22":
        return None
    raw = _tcp_payload_hex(packet)
    banner = ""
    if raw:
        try:
            nl = raw.split(b"\n", 1)[0]
            banner = nl.decode("utf-8", "replace").strip()
        except Exception:
            banner = repr(raw[:80])
    if not banner:
        return None
    rec = _base_record(packet, oui_table, "SSH")
    if not rec:
        return None
    rec["raw_fields"] = {"banner": banner}
    return rec
