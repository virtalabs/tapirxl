from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe
from tapirxl.parser.tables import UUID_PATTERN


def handle(packet, oui_table: dict) -> dict | None:
    cdata = ""
    try:
        if hasattr(packet, "udp") and hasattr(packet.udp, "payload"):
            cdata = bytes.fromhex(str(packet.udp.payload).replace(":", "")).decode(
                "utf-8", "replace"
            )
    except Exception:
        pass
    if not cdata:
        if not hasattr(packet, "xml"):
            return None
        cdata = _safe(packet.xml, "cdata", "") or ""
    if not cdata:
        return None
    rec = _base_record(packet, oui_table, "WS_DISCOVERY")
    if not rec:
        return None
    import re

    m = UUID_PATTERN.search(cdata)
    ws_uuid = m.group(0) if m else None
    ws_vendor_prefix = ws_uuid[0:4].upper() if ws_uuid else None
    ws_series_code = None
    if ws_uuid:
        try:
            ws_series_code = bytes.fromhex(ws_uuid[4:8]).decode("ascii", "ignore").strip()
        except Exception:
            pass
    types_m = re.search(
        r"<[^>]*Types[^>]*>((?:.|[\r\n])*?)</", cdata, re.DOTALL | re.IGNORECASE
    )
    ws_types = types_m.group(1).split() if types_m else []
    scopes_m = re.search(
        r"<[^>]*Scopes[^>]*>((?:.|[\r\n])*?)</", cdata, re.DOTALL | re.IGNORECASE
    )
    ws_scopes = scopes_m.group(1).split() if scopes_m else []
    rec["raw_fields"] = {
        "ws_uuid": ws_uuid,
        "ws_vendor_prefix": ws_vendor_prefix,
        "ws_series_code": ws_series_code,
        "ws_types": ws_types,
        "ws_scopes": ws_scopes,
    }
    return rec
