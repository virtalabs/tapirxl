from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe, _tcp_syn_raw_features


def tcp_syn_infer_os(feat: dict) -> tuple[str, str]:
    """Return (label, confidence tier) from TCP SYN feature dict."""
    ttl = feat.get("ttl")
    ws = feat.get("window_size")
    sack_perm = feat.get("sack_permitted")
    ttl_i = None
    if ttl is not None:
        try:
            ttl_i = int(ttl)
        except ValueError:
            ttl_i = None
    ws_i = None
    if ws is not None:
        try:
            ws_i = int(ws)
        except ValueError:
            ws_i = None

    if ttl_i is not None and ws_i == 64240:
        return "Linux / modern POSIX stack fingerprint", "MEDIUM"
    if ttl_i in (127, 128) and sack_perm:
        win_like = ttl_i == 128 and ws_i == 64240 if ws_i else True
        if win_like:
            return "Windows-like TCP/IP stack", "LOW"
        return "Windows / middlebox TCP/IP stack variant", "LOW"

    if ttl_i == 128:
        return "Likely Windows or Windows-derived stack (TTL≈128)", "LOW"
    if ttl_i in (64, 63, 61):
        return "Likely POSIX / Linux-derived stack (TTL≤64)", "LOW"
    if ttl_i == 255:
        return "Network appliance / IOS-like stack (TTL=255)", "LOW"

    return "Unknown TCP stack (SYN fingerprint)", "LOW"


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "tcp"):
        return None
    syn = _safe(packet.tcp, "flags_syn", "")
    ack = _safe(packet.tcp, "flags_ack", "")
    if str(syn) not in ("1", "True"):
        ss = (_safe(packet.tcp, "flags_str") or "").upper()
        if "SYN" not in ss or "ACK" in ss:
            return None
    if str(ack) in ("1", "True"):
        return None
    rec = _base_record(packet, oui_table, "TCP_SYN")
    if not rec:
        return None
    feats = _tcp_syn_raw_features(packet)
    label, tier = tcp_syn_infer_os(feats)
    rec["raw_fields"] = {
        "syn_features": feats,
        "deterministic_syn_label": label,
        "confidence_hint": tier,
    }
    return rec
