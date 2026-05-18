"""MAC address utilities — no project imports."""

from __future__ import annotations


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    m = mac.strip().upper().replace("-", ":")
    parts = m.split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2) for p in parts)
    return m
