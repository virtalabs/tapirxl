from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "dns") or not hasattr(packet.dns, "ptr_domain_name"):
        return None
    ptr_name = _safe(packet.dns, "ptr_domain_name", "")
    if not ptr_name or not any(x in ptr_name for x in ("._tcp.", "._udp.")):
        return None
    rec = _base_record(packet, oui_table, "DNS_SD_PTR")
    if not rec:
        return None
    rec["raw_fields"] = {"ptr_domain_name": str(ptr_name)}
    return rec
