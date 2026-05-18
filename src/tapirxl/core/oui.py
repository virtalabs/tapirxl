"""OUI lookup — no project imports."""

from __future__ import annotations

from pathlib import Path

from tapirxl.core.mac import normalize_mac

# Medical-device-aware OUI fallback (supplements ieee_oui.txt when absent).
# All entries validated against https://api.maclookup.app/v2/macs/{oui} on 2026-05-13.
OUI_FALLBACK: dict[str, str] = {
    # ── Philips Healthcare ────────────────────────────────────────────────────
    "00:09:5C": "Philips Medical Systems - Cardiac and Monitoring",
    "00:09:FB": "Philips Patient Monitoring",
    "00:25:1B": "Philips CareServant",
    "00:90:20": "Philips Analytical X-Ray B.V.",
    "24:C4:2F": "Philips Lifeline",
    "7C:94:B2": "Philips Healthcare PCCI",
    # ── Dräger ───────────────────────────────────────────────────────────────
    "00:10:5D": "Draeger Medical",
    "00:30:E6": "Draeger Medical Systems, Inc.",
    "F0:E5:C3": "Drägerwerk AG & Co. KGaA",
    # ── GE Healthcare ─────────────────────────────────────────────────────────
    "44:4B:5D": "GE Healthcare",
    "A0:F2:17": "GE Medical Systems (China)",
    # ── Siemens Healthineers ──────────────────────────────────────────────────
    "EC:86:31": "Siemens Healthineers (unverified)",
    # ── Spacelabs Medical ─────────────────────────────────────────────────────
    "00:A0:AA": "Spacelabs Medical",
    # ── Virtualisation / hypervisor ───────────────────────────────────────────
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "00:03:FF": "Microsoft",
    # ── Network infrastructure ────────────────────────────────────────────────
    "00:1B:17": "Palo Alto Networks",
    "98:90:96": "Dell",
    "00:A0:C9": "Intel",
    "00:1B:21": "Intel",
    "E8:D8:D1": "Intel",
    "BC:9F:EF": "Apple",
}


def load_oui_table(path: Path) -> dict[str, str]:
    table = dict(OUI_FALLBACK)
    if path.exists():
        with path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split("\t", 1)
                if len(parts) == 2:
                    table[parts[0].strip().upper()] = parts[1].strip()
    return table


def oui_lookup(mac: str, table: dict[str, str]) -> str:
    if not mac:
        return "UNKNOWN"
    prefix = ":".join(normalize_mac(mac).split(":")[:3])
    return table.get(prefix, "UNKNOWN")
