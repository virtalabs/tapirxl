from __future__ import annotations

from tapirxl.parser._helpers import _base_record
from tapirxl.parser.tables import TLS_SNI_PREFIX_HINTS


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "tls"):
        return None
    sni_candidates: list[str] = []
    try:
        ext = getattr(packet.tls, "handshake_extensions_server_name", None)
        if ext:
            sni_candidates.append(str(ext))
    except Exception:
        pass
    for lay in getattr(packet.tls, "_all_fields", []) or []:
        sa = getattr(lay, "show", "") or ""
        nm = getattr(lay, "name", "") or ""
        if "server_name" in nm.lower():
            sni_candidates.append(sa)
    if not sni_candidates:
        return None
    rec = _base_record(packet, oui_table, "TLS_SNI")
    if not rec:
        return None
    ls = "|".join(sni_candidates).lower()
    hits = [lbl for pat, lbl in TLS_SNI_PREFIX_HINTS if pat.lower() in ls]
    rec["raw_fields"] = {"sni": "|".join(sni_candidates[:3]), "ecosystem_hints": hits}
    return rec
