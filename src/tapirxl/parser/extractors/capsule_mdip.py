from __future__ import annotations

import re

from tapirxl.parser._helpers import (
    _base_record,
    _safe,
    _tcp_syn_raw_features,
    _udp_payload_ascii,
)


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "udp") and not hasattr(packet, "tcp"):
        return None
    port = ""
    if hasattr(packet, "udp"):
        port = str(_safe(packet.udp, "dstport") or "")
    else:
        port = str(_safe(packet.tcp, "dstport") or _safe(packet.tcp, "srcport") or "")
    if port != "5090":
        return None
    rec = _base_record(packet, oui_table, "CAPSULE_MDIP")
    if not rec:
        return None
    capsule_token = ""
    is_tls_syn = False
    if hasattr(packet, "udp"):
        body = _udp_payload_ascii(packet, 4096)
        m = re.search(r"APDUclnt\.0-<([\w\-]{8,})", body)
        if m:
            capsule_token = "APDUclnt.0-<" + m.group(1)
    if hasattr(packet, "tls"):
        capsule_token = "TLS_ClientHello_UDP5090" if capsule_token == "" else capsule_token
        is_tls_syn = True
    if hasattr(packet, "tcp"):
        _tcp_syn_raw_features(packet)
    rec["raw_fields"] = {
        "capsule_token": capsule_token,
        "mdip_udp5090_seen": hasattr(packet, "udp"),
        "mdip_tcp_tls": is_tls_syn,
    }
    return rec
