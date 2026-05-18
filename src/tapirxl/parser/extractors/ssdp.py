from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe, _udp_payload_ascii


def handle(packet, oui_table: dict) -> dict | None:
    dport = _safe(packet.udp, "dstport", "") if hasattr(packet, "udp") else ""
    sport = _safe(packet.udp, "srcport", "") if hasattr(packet, "udp") else ""
    if dport != "1900" and sport != "1900":
        return None
    body = _udp_payload_ascii(packet)
    if not body or ("ssdp:" not in body.lower() and "NOTIFY " not in body):
        if "sonos" not in body.lower() and "chromecast" not in body.lower():
            return None
    rec = _base_record(packet, oui_table, "SSDP")
    if not rec:
        return None
    headers: dict[str, str] = {}
    usn_hint = ""
    server_hint = ""
    for ln in body.split("\r\n"):
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().upper()] = v.strip()
            if k.strip().upper() == "USN":
                usn_hint = v.strip()
            if k.strip().upper() == "SERVER":
                server_hint = v.strip()
    device_hints: list[str] = []
    u = body.upper()
    if "RINCON_" in u or any(x in u for x in ("SONOS_ZPS",)):
        device_hints.append("Sonos networked speaker/controller")
    if "Chromecast" in body or "dial://" in body or "CAST" in u:
        device_hints.append("Chromecast / cast ecosystem device")
    rec["raw_fields"] = {
        "ssdp_headers_sample": headers,
        "server": server_hint,
        "usn": usn_hint,
        "device_hints": device_hints,
    }
    return rec
