"""Pydantic v2 model for InventoryRecord — public wire format.

Conforms to schemas/inventory_record.schema.json. Enum values are cpe:2.3
vendor/product slugs (slots 3 and 4) for upstream CVE/CPE binding.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Build Literal types from enum tuples at import time.
_VendorLiteral = Literal[  # type: ignore[valid-type]
    "microsoft", "philips", "vmware", "paloaltonetworks", "intel"
]
_ProductLiteral = Literal[  # type: ignore[valid-type]
    "windows_7",
    "windows_10",
    "windows_server",
    "intellivue_mx700",
    "brilliance_ict",
    "clinical_collaboration_platform",
    "pan_os",
]
_DeviceClassLiteral = Literal[  # type: ignore[valid-type]
    "CT",
    "MR",
    "US",
    "CR",
    "DX",
    "MG",
    "NM",
    "PT",
    "patient_monitor",
    "clinical_workstation",
    "workstation",
    "server",
    "pacs",
    "firewall",
    "dhcp_server",
]


class InventoryRecord(BaseModel):
    """One passively-observed device record, emitted as JSONL when --json is set.

    Required fields mirror the wire contract in
    ``schemas/inventory_record.schema.json``: ``ip_address``, ``mac_address``,
    ``open_ports``, and ``confidence`` must always be present (``confidence``
    may be ``None`` for skipped hosts; ``open_ports`` may be empty).
    """

    hostname: str | None = None
    ip_address: str
    mac_address: str
    vendor: _VendorLiteral | None = None
    product: _ProductLiteral | None = None
    version: str | None = None
    device_class: _DeviceClassLiteral | None = None
    open_ports: list[int] = Field(...)
    confidence: Literal["HIGH", "MEDIUM", "LOW"] | None = Field(...)
