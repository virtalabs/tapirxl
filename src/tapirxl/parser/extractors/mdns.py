from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


def handle_txt(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "dns") or not hasattr(packet.dns, "txt"):
        return None
    rec = _base_record(packet, oui_table, "MDNS_TXT")
    if not rec:
        return None
    txt_raw_str = _safe(packet.dns, "txt", "")
    txt_entries = [e.strip() for e in str(txt_raw_str).split(";") if e.strip()]
    txt_parsed: dict[str, str] = {}
    for entry in txt_entries:
        if "=" in entry:
            k, _, v = entry.partition("=")
            txt_parsed[k.strip()] = v.strip()
    rec["raw_fields"] = {
        "resp_name": _safe(packet.dns, "resp_name"),
        "mdns_txt_raw": txt_entries,
        "mdns_txt_parsed": txt_parsed,
    }
    return rec


def handle_a(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "dns") or not hasattr(packet.dns, "a"):
        return None
    rec = _base_record(packet, oui_table, "MDNS_A")
    if not rec:
        return None
    rec["raw_fields"] = {
        "mdns_hostname": _safe(packet.dns, "resp_name"),
        "resolved_ip": _safe(packet.dns, "a"),
    }
    return rec
