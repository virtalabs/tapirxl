from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe
from tapirxl.parser.tables import SNMP_SYSDESCR_PREFIX_LABELS


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "snmp"):
        return None
    rec = _base_record(packet, oui_table, "SNMP")
    if not rec:
        return None
    sysdescr = ""
    sysobj = ""
    sysname = ""
    comm = ""
    try:
        sysdescr = str(_safe(packet.snmp, "value_string_raw", "") or "")[:4096]
    except Exception:
        sysdescr = str(getattr(packet.snmp, "value_string", "") or "")[:4096]

    descr_label = ""
    for prefix, lab in SNMP_SYSDESCR_PREFIX_LABELS:
        if prefix.lower() in sysdescr.lower():
            descr_label = lab
            break
    try:
        sysname = str(_safe(packet.snmp, "sysName_raw", "") or "")[:256]
        sysobj = str(_safe(packet.snmp, "sysOID", "") or _safe(packet.snmp, "objid", "") or "")[
            :256
        ]
        comm = _safe(packet.snmp, "community_string_raw", "") or ""
    except Exception:
        pass
    rec["raw_fields"] = {
        "sys_descr": sysdescr,
        "sys_object_id": sysobj,
        "sys_name": sysname,
        "community_present": bool(str(comm).strip()),
        "deterministic_descr_label": descr_label,
    }
    return rec
