"""Static lookup tables for the parser layer.

Hardcoded constants are used as fallbacks when static/*.json files are absent.
JSON files are loaded relative to CWD (i.e., repo root) at import time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


def _load_json(name: str, fallback: object) -> object:
    p = Path.cwd() / "static" / name
    try:
        return json.loads(p.read_text())
    except Exception:
        return fallback


FINGERBANK_DHCP_55: dict[str, str] = _load_json(  # type: ignore[assignment]
    "fingerbank_dhcp_55.json",
    {
        "1,3,6,26,51,115,249": "Windows DHCP client typical",
        "1,3,6,15,31,33,43,44,46,47,121,249": "Windows 7 / Server 2008 R2 DHCP client typical",
        "1,121,249,253": "ChromeOS / DHCP minimal",
        "1,3,6,28,119,252": "Android DHCP client typical",
    },
)

DICOM_IMPL_UID_ARCS: dict[str, str] = _load_json(  # type: ignore[assignment]
    "dicom_impl_uid_arcs.json",
    {
        "1.3.46.670589.30.": "Philips Eleva platform",
        "1.3.46.": "Philips Healthcare",
        "1.3.12.2.1107.": "Siemens Healthineers",
        "1.2.840.113619.": "GE Healthcare",
        "1.2.276.0.7230010.3.": "OFFIS DCMTK",
    },
)

HL7_SENDING_APPS_CANONICAL: dict[str, str] = _load_json(  # type: ignore[assignment]
    "hl7_sending_apps.json",
    {
        "EPIC": "Epic (EHR integration)",
        "CERNER": "Cerner (EHR integration)",
        "Meditech": "Meditech HIS",
        "MIRTH": "Mirth integration engine",
        "Mirth": "Mirth integration engine",
    },
)

_snmp_raw = _load_json(
    "snmp_sysobjectid_arcs.json",
    {
        "sysdescr_prefix_labels": [
            ["Cisco IOS", "Cisco IOS network device"],
            ["Cisco Catalyst", "Cisco Catalyst switch"],
            ["Philips Medical", "Philips medical networked device"],
            ["HP-", "HP network printer/device"],
            ["Brother", "Brother network printer/device"],
        ]
    },
)
SNMP_SYSDESCR_PREFIX_LABELS: list[tuple[str, str]] = [
    (pair[0], pair[1])
    for pair in (
        _snmp_raw.get("sysdescr_prefix_labels")
        if isinstance(_snmp_raw, dict)
        else _snmp_raw
    )
    or []
]

KNOWN_MEDICAL_UUID_PREFIXES: set[str] = {"5048", "4745", "5349", "4452", "4243"}

CLINICAL_SERVICE_STRINGS: tuple[str, ...] = ("_dicom._tcp", "_hl7._tcp", "_fhir._tcp")

KNOWN_WS_TYPES_PREFIXES: tuple[str, ...] = (
    "urn:schemas-wsdp-org",
    "http://docs.oasis-open.org",
    "urn:schemas-upnp-org",
    "urn:schemas-philips-com",
    "urn:schemas-ge-com",
    "urn:schemas-siemens-com",
    "urn:schemas-microsoft-com",
    "urn:ihe-pcd:",
    "http://schemas.xmlsoap.org/ws/2005/04/discovery",
)

PHILIPS_INTELLIVUE_SERIES: dict[str, str] = {
    "BH": "Philips IntelliVue MX700/MX800",
    "BV": "Philips IntelliVue MX400/MX450",
    "GD": "Philips IntelliVue X3/X2",
}

PHILIPS_WS_TYPES_CANONICAL: dict[str, str] = {
    "http://schemas.xmlsoap.org/ws/2005/04/discovery": "WS-Discovery 2005 legacy namespace",
    "urn:ihe-pcd:device:": "IHE PCD patient care device",
    "urn:ihe:pcd:": "IHE PCD patient care device",
    "urn:oid:1.3.6.1.4.1.19376.1.6.1.": "IEEE 11073 / IHE PCD device-type OID arc",
}

PHILIPS_MDNS_TXT_KEYWORDS: list[tuple[str, str, str]] = [
    ("IntelliVue", "device_family", "Philips IntelliVue patient monitor"),
    ("intellivue", "device_family", "Philips IntelliVue patient monitor"),
    ("Ingenuity", "device_family", "Philips Ingenuity CT scanner"),
    ("Achieva", "device_family", "Philips Achieva MR scanner"),
    ("IU22", "device_family", "Philips iU22 ultrasound"),
    ("EPIQ", "device_family", "Philips EPIQ ultrasound"),
    ("PMS_ELEVA", "platform", "Philips Eleva imaging platform"),
    ("Eleva", "platform", "Philips Eleva imaging platform"),
    ("PHILIPS_MX", "device_family", "Philips IntelliVue MX-series monitor"),
    ("Philips", "vendor", "Philips Healthcare"),
]

DHCP_VENDOR_CLASS_MEDICAL: list[tuple[str, str]] = [
    ("Philips IntelliVue", "Philips IntelliVue patient monitor"),
    ("IntelliVue", "Philips IntelliVue patient monitor"),
    ("Philips Patient", "Philips patient monitoring"),
    ("Natus Medical", "Natus Medical neurological device"),
    ("Natus", "Natus Medical device"),
    ("Spacelabs", "Spacelabs patient monitor"),
    ("CapsuleTech", "Capsule MDIP / patient connectivity"),
    ("Capsule", "Capsule patient connectivity middleware"),
]

TLS_SNI_PREFIX_HINTS: list[tuple[str, str]] = [
    ("sentinelone", "sentinelone_edr"),
    ("events.data.microsoft.com", "windows_telemetry"),
    ("delivery.mp.microsoft.com", "windows_update_delivery"),
    ("do.dsp.mp.microsoft.com", "windows_delivery_optimization"),
    ("teamviewer", "teamviewer_remote_access"),
]

DICOM_PHILIPS_IMAGE_UID_ARC: str = "1.2.840.113704."

UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

DISPLAY_FILTER: str = (
    "udp.port == 3702 or "
    "udp.port == 5353 or "
    "udp.port == 5355 or "
    "udp.port == 1900 or "
    "udp.port == 5090 or "
    "arp or "
    "(tcp.flags.syn == 1 and tcp.flags.ack == 0) or "
    "tls.handshake.type == 1 or "
    "smb2.cmd == 0 or "
    "smb2.cmd == 1 or "
    "ntlmssp or "
    "kerberos or "
    "dns or "
    "(tcp.port == 22) or "
    "(tcp.port == 104 or tcp.port == 2104 or tcp.port == 2762 "
    "or tcp.srcport == 104 or tcp.srcport == 2104 or tcp.srcport == 2762) or "
    "dhcp or dhcpv6 or "
    '(tcp.payload contains "MSH|") or '
    "snmp or "
    "_ws.expert"
)

PIPELINE_1_PROTOS: set[str] = {
    "WS_DISCOVERY", "MDNS_TXT", "MDNS_A", "DNS_SD_PTR", "LLMNR", "SSDP", "CAPSULE_MDIP", "ARP",
}
PIPELINE_2_PROTOS: set[str] = {
    "TCP_SYN", "TLS_SNI", "SMB2", "SMB_NTLMSSP", "KERBEROS", "DNS_LOOKUP", "SSH",
}
PIPELINE_3_PROTOS: set[str] = {"DICOM", "DHCP", "SNMP", "HL7_MLLP"}

CONTRADICTION_MESSAGES: dict[str, str] = {
    "C1": "OUI vendor signal disagrees with DICOM attribution (OUI_DICOM_VENDOR_MISMATCH)",
    "C2": (
        "mDNS/Chromecast-style identity clashes with deterministic WS-Discovery / OUI "
        "attribution (MDNS_SPOOF_SUSPECTED)"
    ),
    "C3": (
        "Philips WS-Discovery present but non-Philips / conflicting DICOM implementation arc "
        "(PHILIPS_WSDISC_VS_NON_PHILIPS_DICOM)"
    ),
    "C4": (
        "LLMNR hostname materially differs from mDNS authoritative name "
        "(DOMAIN_HOSTNAME_MISMATCH)"
    ),
}
