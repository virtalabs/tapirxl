"""Deterministic InventoryRecord builder.

Pure functions over HostEnvelope dicts; no LM, no project imports outside
`core/`. Lives in `core/` because both `parser/cli.py` (for `mdt parse --json`)
and `agent/inventory.py` (for `mdt agent --json` + the markdown report)
consume it (see CLAUDE.md N1 — `parser/` and `agent/` must not import each
other).

Schema: ``schemas/inventory_record.schema.json``.
"""

from __future__ import annotations

from tapirxl.core.enums import (
    CPE_PRODUCT_ENUM,
    CPE_VENDOR_ENUM,
    DEVICE_CLASS_ENUM,
    _env_dicom_assoc_results,
    enum_or_none,
    to_cpe_product,
    to_cpe_vendor,
    to_device_class,
)

CONF_RANK: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "TRIAGE_ONLY": 1}

DNS_SD_PORT_MAP: dict[str, int] = {
    "_dicom._tcp": 104,
    "_hl7._tcp": 2575,
    "_http._tcp": 80,
    "_https._tcp": 443,
    "_printer._tcp": 515,
    "_ipp._tcp": 631,
    "_ipps._tcp": 631,
    "_smb._tcp": 445,
    "_ssh._tcp": 22,
    "_ftp._tcp": 21,
    "_sftp-ssh._tcp": 22,
    "_rdp._tcp": 3389,
    "_workstation._tcp": 9,
    "_device-info._tcp": 0,
    "_airplay._tcp": 7000,
    "_raop._tcp": 5000,
}


def _filter_conf(conf: str) -> str:
    c = conf.strip().upper()
    return c if c in CONF_RANK else "LOW"


def _effective_inventory_conf(row: dict, fused: dict | None, no_llm: bool) -> str:
    if fused and not no_llm:
        return _filter_conf(str(fused.get("confidence", "LOW")))

    routing = (row.get("triage") or {}).get("routing")
    if routing == "DETERMINISTIC_FINAL":
        cons = (row.get("triage") or {}).get("deterministic_consensus") or {}
        return _filter_conf(str(cons.get("confidence", "HIGH")))
    if routing == "STAMP_LOW":
        return "LOW"

    if row.get("signal_count") == 1 and not row.get("floor_triggers"):
        return "LOW"
    return "TRIAGE_ONLY"


def _derive_hostname(envelope: dict) -> str | None:
    for key in (
        "dhcp_hostname",
        "llmnr_hostname",
        "ntlmssp_target_computer",
        "ntlmssp_workstation",
        "mdns_hostname",
    ):
        v = envelope.get(key)
        if v:
            s = str(v).strip()
            if s:
                return s
    return None


def _derive_version(envelope: dict) -> str | None:
    for assoc in _env_dicom_assoc_results(envelope):
        sv = (assoc.get("dicom_software_versions") or "").strip()
        if sv:
            return sv
    txt = envelope.get("mdns_txt_parsed") or {}
    if isinstance(txt, dict):
        for key in ("firmware", "fw_version", "version", "sw_version", "swversion"):
            val = txt.get(key)
            if val:
                return str(val)
    return None


def _derive_open_ports(envelope: dict) -> list[int]:
    ports: set[int] = set()

    if envelope.get("ws_uuid"):
        ports.add(3702)

    if (
        envelope.get("mdns_hostname")
        or envelope.get("mdns_txt_raw")
        or envelope.get("mdns_txt_parsed")
    ):
        ports.add(5353)

    if envelope.get("llmnr_hostname") or envelope.get("llmnr_queries"):
        ports.add(5355)

    capsule = envelope.get("capsule_mdip") or {}
    if capsule.get("udp5090") or capsule.get("tls"):
        ports.add(5090)

    if envelope.get("ssdp_observations"):
        ports.add(1900)

    for svc in envelope.get("dns_sd_services") or []:
        if not isinstance(svc, str):
            continue
        key = svc.removesuffix(".local").rstrip(".")
        port = DNS_SD_PORT_MAP.get(key)
        if port:
            ports.add(port)

    return sorted(ports)


def build_jsonl_record(envelope: dict, fused: dict | None, *, no_llm: bool = True) -> dict:
    vendor = enum_or_none(to_cpe_vendor(envelope), CPE_VENDOR_ENUM)
    product = enum_or_none(to_cpe_product(envelope), CPE_PRODUCT_ENUM)
    device_class = enum_or_none(to_device_class(envelope), DEVICE_CLASS_ENUM)

    conf = _effective_inventory_conf(envelope, fused, no_llm)
    if conf == "TRIAGE_ONLY":
        conf = "LOW"

    return {
        "hostname": _derive_hostname(envelope),
        "ip_address": envelope.get("ip") or "",
        "mac_address": envelope.get("mac") or "",
        "vendor": vendor,
        "product": product,
        "version": _derive_version(envelope),
        "device_class": device_class,
        "open_ports": _derive_open_ports(envelope),
        "confidence": conf,
    }
