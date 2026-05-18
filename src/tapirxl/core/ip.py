"""IP address utilities — no project imports."""

from __future__ import annotations


def ip_sort_key(ip: str) -> tuple:
    try:
        return tuple(int(o) for o in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)
