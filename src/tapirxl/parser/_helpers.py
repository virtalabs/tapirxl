"""Low-level pyshark packet access helpers shared across all extractors."""
from __future__ import annotations

import struct

from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import oui_lookup


def _safe(obj, attr, default=None):
    try:
        val = getattr(obj, attr, default)
        return val if val is not None else default
    except Exception:
        return default


def _packet_src_identity(packet, oui_table: dict) -> tuple[str, str | None, str]:
    """Return (mac_normalized, ipv4_src_or_None, oui_vendor)."""
    eth_mac = normalize_mac(_safe(packet.eth, "src", "") if hasattr(packet, "eth") else "")
    ipv4 = _safe(packet.ip, "src") if hasattr(packet, "ip") else None

    dhcp_mac = ""
    bootp_attrs = getattr(packet, "bootp", None)
    if bootp_attrs:
        dhcp_mac = normalize_mac(
            _safe(bootp_attrs, "hardware_mac_address", "")
            or _safe(bootp_attrs, "mac_addr", "")
            or _safe(bootp_attrs, "client_mac_address", "")
        )

    mac = eth_mac or dhcp_mac
    return mac or "", ipv4, oui_lookup(mac, oui_table)


def _base_record(packet, oui_table: dict, protocol: str) -> dict | None:
    """Layer-1 record keyed by ethernet MAC (required for host grouping)."""
    try:
        mac, ipv4, oui_from_pkt = _packet_src_identity(packet, oui_table)
        if not mac:
            return None
        return {
            "src_ip": ipv4 or "0.0.0.0",
            "src_mac": normalize_mac(mac),
            "src_oui": oui_from_pkt if oui_from_pkt != "UNKNOWN" else oui_lookup(mac, oui_table),
            "protocol": protocol,
            "raw_fields": {},
            "expert_flag": False,
            "expert_message": "",
            "timestamp": float(packet.sniff_timestamp),
        }
    except Exception:
        return None


def _udp_payload_ascii(packet, max_chars: int = 65536) -> str:
    try:
        if hasattr(packet, "udp") and hasattr(packet.udp, "payload"):
            raw = bytes.fromhex(str(packet.udp.payload).replace(":", ""))
            return raw[:max_chars].decode("latin-1", "replace")
    except Exception:
        pass
    return ""


def _tcp_payload_hex(packet) -> bytes:
    try:
        ld = getattr(packet, "data", None)
        if ld and hasattr(ld, "data"):
            hx = getattr(ld.data, "data", None)
            if hx:
                return bytes.fromhex(str(hx).replace(":", ""))
        if hasattr(packet, "tcp"):
            tpl = getattr(packet.tcp, "payload", None)
            if tpl:
                return bytes.fromhex(str(tpl).replace(":", ""))
    except Exception:
        pass
    return b""


def _tcp_syn_raw_features(packet) -> dict:
    feats: dict = {}
    try:
        if not hasattr(packet, "tcp"):
            return feats
        feats["ttl"] = _safe(packet.ip, "ttl") if hasattr(packet, "ip") else None
        feats["window_size"] = _safe(packet.tcp, "window_size_value", None)
        if feats["window_size"] is None:
            feats["window_size"] = _safe(packet.tcp, "window_size", None)
        op_list = getattr(packet.tcp, "options", "")
        feats["tcp_options_repr"] = str(op_list or "")
        for opt in getattr(packet.tcp, "_all_fields", []):
            lk = getattr(opt, "showname", "") or getattr(opt, "abbr", "")
            if "mss" in str(lk).lower():
                feats.setdefault("mss", []).append(getattr(opt, "show", None))
            if "window scale" in str(lk).lower() or "wscale" in str(lk).lower():
                feats["wscale"] = getattr(opt, "show", None)
            if "sack_perm" in str(lk).lower() or "SACK permitted" in str(lk):
                feats["sack_permitted"] = True
            if "timestamp" in str(lk).lower():
                feats["timestamp"] = True
    except Exception:
        pass
    return feats


def _slice_ip_tcp_payload(packet) -> bytes:
    """RFC-style slice of Ethernet+IPv4+TCP payload using dissector header lengths."""
    try:
        raw_hex = getattr(packet.frame_info, "raw_value", None)
        if not raw_hex or not hasattr(packet, "ip") or not hasattr(packet, "tcp"):
            return _tcp_payload_hex(packet)
        frame = bytes.fromhex(str(raw_hex).replace(":", "").replace(" ", ""))
        off = 14 if hasattr(packet, "eth") else 0
        hdr_len_txt = _safe(packet.ip, "hdr_len_raw", "") or _safe(packet.ip, "hdr_len")
        hdr_len_txt = "" if hdr_len_txt is None else str(hdr_len_txt)
        if hdr_len_txt.lower().startswith("0x"):
            ip_hdr = int(hdr_len_txt, 16)
        else:
            try:
                val = float(hdr_len_txt)
                vi = int(val)
                ip_hdr = vi * 4 if vi <= 15 else vi
            except Exception:
                ip_hdr = 20
        if ip_hdr <= 5:
            ip_hdr *= 4
        if ip_hdr > 255 or ip_hdr < 20:
            ip_hdr = 20

        tl_raw = _safe(packet.tcp, "hdr_len_raw", "") if hasattr(packet, "tcp") else None
        tl_raw_s = "" if tl_raw is None else str(tl_raw)
        if tl_raw_s.lower().startswith("0x"):
            tcp_hdrlen = int(tl_raw_s, 16)
        elif hasattr(packet, "tcp"):
            tl_word = _safe(packet.tcp, "hdr_len")
            tls = str(tl_word) if tl_word is not None else "5"
            try:
                tli = int(tls, 16) if tls.lower().startswith("0x") else int(float(tls))
                tcp_hdrlen = tli * 4 if tli <= 15 else tli
            except Exception:
                tcp_hdrlen = 20
        else:
            tcp_hdrlen = 20
        if tcp_hdrlen < 20:
            tcp_hdrlen *= 4
        if tcp_hdrlen > 255 or tcp_hdrlen < 20:
            tcp_hdrlen = 20
        start_pay = min(len(frame), off + ip_hdr + tcp_hdrlen)
        payload = frame[start_pay:]
        return payload if payload else _tcp_payload_hex(packet)
    except Exception:
        return _tcp_payload_hex(packet)


def _dicom_tag_value_explicit_vr_le(
    payload: bytes, group: int, element: int, vr: bytes
) -> str:
    """Extract a single DICOM data-element value (Explicit VR Little Endian)."""
    needle = struct.pack("<HH", group, element) + vr
    idx = payload.find(needle)
    if idx < 0:
        return ""
    off = idx + len(needle)
    if off + 2 > len(payload):
        return ""
    length = struct.unpack_from("<H", payload, off)[0]
    val_off = off + 2
    if val_off + length > len(payload) or length > 256:
        return ""
    raw = payload[val_off : val_off + length]
    try:
        return raw.decode("ascii", "replace").strip().strip("\x00").rstrip()
    except Exception:
        return ""
