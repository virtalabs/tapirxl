from __future__ import annotations

from tapirxl.parser._helpers import _base_record


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "kerberos"):
        return None
    realm = getattr(packet.kerberos, "realm_string", "") or getattr(packet.kerberos, "realm", "")
    cname = getattr(packet.kerberos, "request_cname_string", "") or getattr(
        packet.kerberos, "username", ""
    )
    rec = _base_record(packet, oui_table, "KERBEROS")
    if not rec:
        return None
    rec["raw_fields"] = {
        "realm": str(realm) if realm else "",
        "client_name_hint": str(cname) if cname else "",
    }
    return rec
