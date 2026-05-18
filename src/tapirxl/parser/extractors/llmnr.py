from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "llmnr"):
        return None
    rec = _base_record(packet, oui_table, "LLMNR")
    if not rec:
        return None
    rec["raw_fields"] = {
        "query_name": _safe(packet.llmnr, "dns_qry_name"),
        "resp_name": _safe(packet.llmnr, "dns_resp_name"),
    }
    return rec
