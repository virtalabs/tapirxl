from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


def handle(packet, oui_table: dict) -> dict | None:
    try:
        layer_names = [lay.layer_name for lay in packet.layers]
        if "_ws_expert" not in layer_names:
            return None
        expert_layer = packet["_ws.expert"]
        sev = _safe(expert_layer, "severity", 0)
        if sev is None or int(str(sev)) < 4:
            return None
        rec = _base_record(packet, oui_table, "EXPERT")
        if not rec:
            return None
        rec["expert_flag"] = True
        rec["expert_message"] = str(_safe(expert_layer, "message", ""))
        return rec
    except Exception:
        return None
