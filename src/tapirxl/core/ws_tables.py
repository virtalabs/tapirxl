"""Shared WS-Discovery / mDNS lookup tables.

Lives in `core/` because both `parser/` and `agent/` need these constants
(see CLAUDE.md hard rule N1: `agent/` and `parser/` MUST NOT import each
other). No project imports.
"""

from __future__ import annotations

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
