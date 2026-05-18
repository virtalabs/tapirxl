from __future__ import annotations

from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import oui_lookup
from tapirxl.parser._helpers import _safe


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "arp"):
        return None
    opcode = str(_safe(packet.arp, "opcode"))
    mac_src = normalize_mac(str(_safe(packet.arp, "src_hw_mac")))
    ipa = _safe(packet.arp, "src_proto_ipv4") or _safe(packet.arp, "dst_proto_ipv4")
    if opcode == "2" and mac_src:
        gratuitous = ipa and str(ipa) == (
            _safe(packet.arp, "dst_proto_ipv4") or _safe(packet.arp, "src_proto_ipv4")
        )
    else:
        gratuitous = False
    emitter = normalize_mac(_safe(packet.eth, "src")) if hasattr(packet, "eth") else mac_src
    if not emitter:
        return None
    return {
        "src_ip": str(ipa) if ipa else "0.0.0.0",
        "src_mac": emitter,
        "src_oui": oui_lookup(emitter, oui_table),
        "protocol": "ARP",
        "raw_fields": {
            "opcode": opcode,
            "sha": mac_src,
            "spa": _safe(packet.arp, "src_proto_ipv4"),
            "tpa": _safe(packet.arp, "dst_proto_ipv4"),
            "gratuitous_arp_hint": gratuitous,
        },
        "expert_flag": False,
        "expert_message": "",
        "timestamp": float(packet.sniff_timestamp),
    }
