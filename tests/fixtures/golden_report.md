# Asset Inventory — Broadcast Protocol Signal Fusion (PoC v2.0 envelope)

**Capture file:** `synthetic_philips_demo`
**Analysis date:** `2026-05-15`
**Analyst:** VirtaLabs (automated — tapirxl)
**Classification:** CONFIDENTIAL — HIPAA Sensitive
**Mode:** triage-only (--no-llm) | output confidence filter `L` (min rank `1`)

---

## Summary

| Category | Count |
|----------|-------|
| Total unique MAC hosts analyzed | 8 |
| Skipped hosts (routing=SKIP) | 0 |
| Routed STAMP_LOW (single weak signal) | 1 |
| DETERMINISTIC_FINAL (consensus sans fusion) | 2 |
| Submitted to LM fusion / normalization path | 5 |
| Rows visible — LOW stamped hosts | 1 |
| Rows visible — TRIAGE_ONLY (fusion pending) | 7 |

---

## Detailed Asset Records
## 10.10.10.21 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.10.21` |
| MAC | `00:09:FB:BD:75:6D` |
| Host ID | `00:09:fb:bd:75:6d` |
| OUI Vendor | Philips Patient Monitoring |
| Hostname | MX700-bed12 |
| Vendor (CPE) | `philips` |
| Product (CPE) | `intellivue_mx700` |
| Device class (enum) | `patient_monitor` |
| Pipelines fired | `1, 3` |
| Processing path | `ENQUEUE_FULL` |
| Triage routing | `ENQUEUE_FULL` |
| Deterministic consensus | `Philips IntelliVue MX700/MX800 (MEDIUM)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** deterministic `Philips IntelliVue MX700/MX800` (**HIGH**)
```json
{
  "ws_discovery_seen": true,
  "deterministic_label": "Philips IntelliVue MX700/MX800",
  "deterministic_confidence": "HIGH"
}
```

- **PIPELINE_2:** *(not triggered)*

- **PIPELINE_3:** deterministic `Philips IntelliVue patient monitor` (**MEDIUM**)
```json
{
  "dhcp": [
    {
      "option12_hostname_hint": "MX700-bed12",
      "option60_vendor_class": "Philips IntelliVue",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        28,
        51,
        58,
        59
      ],
      "option55_key_guess": "1,3,6,15,28,51,58,59",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "Philips IntelliVue patient monitor",
      "dhcp_message_type": "discover",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0xaabbccdd\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:fb:bd:75:6d\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Discover)\n\tLength: 1\n\tDHCP: Discover (1)\n\tHost Name: MX700-bed12\n\tVendor class identifier: Philips IntelliVue\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 11\n\tLength: 18\n\tLength: 8\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (28) Broadcast Address\n\tParameter Request List Item: (51) IP Address Lease Time\n\tParameter Request List Item: (58) Renewal Time Value\n\tParameter Request List Item: (59) Rebinding Time Value\n"
    },
    {
      "option12_hostname_hint": "MX700-bed12",
      "option60_vendor_class": "Philips IntelliVue",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        28,
        51,
        58,
        59
      ],
      "option55_key_guess": "1,3,6,15,28,51,58,59",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "Philips IntelliVue patient monitor",
      "dhcp_message_type": "request",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0xaabbccd0\n\tSeconds elapsed: 2\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:fb:bd:75:6d\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Request)\n\tLength: 1\n\tDHCP: Request (3)\n\tHost Name: MX700-bed12\n\tVendor class identifier: Philips IntelliVue\n\tRequested IP Address: 10.10.10.21\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (50) Requested IP Address (10.10.10.21)\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 11\n\tLength: 18\n\tLength: 4\n\tLength: 8\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (28) Broadcast Address\n\tParameter Request List Item: (51) IP Address Lease Time\n\tParameter Request List Item: (58) Renewal Time Value\n\tParameter Request List Item: (59) Rebinding Time Value\n"
    }
  ],
  "deterministic_label": "Philips IntelliVue patient monitor",
  "deterministic_confidence": "MEDIUM"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `50484248-4332-3638-3631-0009fbbd756d`
- WS-Discovery Types: urn:ihe-pcd:device:patientmonitor
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: —
- LLMNR hostname: —

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
## 10.10.10.30 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.10.30` |
| MAC | `00:90:20:AA:BB:01` |
| Host ID | `00:90:20:aa:bb:01` |
| OUI Vendor | Philips Analytical X-Ray B.V. |
| Hostname | BRILL-CT01 |
| Vendor (CPE) | `philips` |
| Product (CPE) | `brilliance_ict` |
| Device class (enum) | `—` |
| Pipelines fired | `2, 3` |
| Processing path | `DETERMINISTIC_FINAL` |
| Triage routing | `DETERMINISTIC_FINAL` |
| Deterministic consensus | `Philips modality / DICOM-speaking device (HIGH)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** deterministic `Likely Windows or Windows-derived stack (TTL≈128)` (**LOW**)
```json
{
  "syn_fingerprints": [
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    }
  ],
  "deterministic_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
  "deterministic_confidence": "LOW"
}
```

- **PIPELINE_3:** deterministic `Philips modality / DICOM-speaking device` (**HIGH**)
```json
{
  "dhcp": [
    {
      "option12_hostname_hint": "BRILL-CT01",
      "option60_vendor_class": "Philips Brilliance iCT",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        28,
        51,
        58,
        59
      ],
      "option55_key_guess": "1,3,6,15,28,51,58,59",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "discover",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x33cc0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:90:20:aa:bb:01\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Discover)\n\tLength: 1\n\tDHCP: Discover (1)\n\tHost Name: BRILL-CT01\n\tVendor class identifier: Philips Brilliance iCT\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 10\n\tLength: 22\n\tLength: 8\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (28) Broadcast Address\n\tParameter Request List Item: (51) IP Address Lease Time\n\tParameter Request List Item: (58) Renewal Time Value\n\tParameter Request List Item: (59) Rebinding Time Value\n"
    },
    {
      "option12_hostname_hint": "BRILL-CT01",
      "option60_vendor_class": "Philips Brilliance iCT",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        28,
        51,
        58,
        59
      ],
      "option55_key_guess": "1,3,6,15,28,51,58,59",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "request",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x33cc0002\n\tSeconds elapsed: 2\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:90:20:aa:bb:01\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Request)\n\tLength: 1\n\tDHCP: Request (3)\n\tHost Name: BRILL-CT01\n\tVendor class identifier: Philips Brilliance iCT\n\tRequested IP Address: 10.10.10.30\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (50) Requested IP Address (10.10.10.30)\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 10\n\tLength: 22\n\tLength: 4\n\tLength: 8\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (28) Broadcast Address\n\tParameter Request List Item: (51) IP Address Lease Time\n\tParameter Request List Item: (58) Renewal Time Value\n\tParameter Request List Item: (59) Rebinding Time Value\n"
    }
  ],
  "dicom_association": [
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "01",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [
          "1.3.46.670589.30.->Philips Eleva platform",
          "1.3.46.->Philips Healthcare"
        ],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "04",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [
          "1.2.840.113704."
        ],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "04",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "CT",
        "dicom_manufacturer": "Philips",
        "dicom_manufacturer_model": "Brilliance iCT",
        "dicom_software_versions": "4.1.6"
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    }
  ],
  "deterministic_label": "Philips modality / DICOM-speaking device",
  "deterministic_confidence": "HIGH"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: —
- LLMNR hostname: —

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
## 10.10.10.40 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.10.40` |
| MAC | `E8:D8:D1:AA:BB:02` |
| Host ID | `e8:d8:d1:aa:bb:02` |
| OUI Vendor | Intel |
| Hostname | ACMECT01 |
| Vendor (CPE) | `microsoft` |
| Product (CPE) | `windows_7` |
| Device class (enum) | `workstation` |
| Pipelines fired | `2, 3` |
| Processing path | `ENQUEUE_FULL` |
| Triage routing | `ENQUEUE_FULL` |
| Deterministic consensus | `sentinelone_edr|windows_telemetry (MEDIUM)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** deterministic `sentinelone_edr|windows_telemetry` (**MEDIUM**)
```json
{
  "syn_fingerprints": [
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4:01:03:03:08:04:02:00:00"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    },
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    },
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    },
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    },
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    },
    {
      "syn_features": {
        "ttl": "128",
        "window_size": "8192",
        "tcp_options_repr": "02:04:05:b4:01:03:03:08:04:02:00:00"
      },
      "deterministic_syn_label": "Likely Windows or Windows-derived stack (TTL\u2248128)",
      "confidence_hint": "LOW"
    }
  ],
  "sni_hits": [
    {
      "sni": "usea1-016.sentinelone.net",
      "ecosystem_hints": [
        "sentinelone_edr"
      ]
    },
    {
      "sni": "events.data.microsoft.com",
      "ecosystem_hints": [
        "windows_telemetry"
      ]
    }
  ],
  "smb2_negotiate": [
    {
      "dialects_sample": "0x0202,0x0210",
      "dialect_revision": "",
      "signing_enabled": ""
    },
    {
      "dialects_sample": "",
      "dialect_revision": "",
      "signing_enabled": ""
    },
    {
      "dialects_sample": "",
      "dialect_revision": "",
      "signing_enabled": ""
    }
  ],
  "deterministic_label": "sentinelone_edr|windows_telemetry",
  "deterministic_confidence": "MEDIUM"
}
```

- **PIPELINE_3:** deterministic `Windows 7 / Server 2008 R2 DHCP client typical` (**MEDIUM**)
```json
{
  "dhcp": [
    {
      "option12_hostname_hint": "ACMECT01",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        121,
        249
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,121,249",
      "fingerbank_dhcp_hit": "Windows 7 / Server 2008 R2 DHCP client typical",
      "vendor_medical_hint": "",
      "dhcp_message_type": "discover",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x77aabb01\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: e8:d8:d1:aa:bb:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Discover)\n\tLength: 1\n\tDHCP: Discover (1)\n\tHost Name: ACMECT01\n\tVendor class identifier: MSFT 5.0\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 8\n\tLength: 8\n\tLength: 12\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (43) Vendor-Specific Information\n"
    },
    {
      "option12_hostname_hint": "ACMECT01",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        121,
        249
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,121,249",
      "fingerbank_dhcp_hit": "Windows 7 / Server 2008 R2 DHCP client typical",
      "vendor_medical_hint": "",
      "dhcp_message_type": "request",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x77aabb02\n\tSeconds elapsed: 2\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: e8:d8:d1:aa:bb:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Request)\n\tLength: 1\n\tDHCP: Request (3)\n\tHost Name: ACMECT01\n\tVendor class identifier: MSFT 5.0\n\tRequested IP Address: 10.10.10.40\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (50) Requested IP Address (10.10.10.40)\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 8\n\tLength: 8\n\tLength: 4\n\tLength: 12\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (43) Vendor-Specific Information\n"
    }
  ],
  "deterministic_label": "Windows 7 / Server 2008 R2 DHCP client typical",
  "deterministic_confidence": "MEDIUM"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: DC1.acmehosp.local, PACSARCH01, ACMECT01, CCPLATFORM01, ACMEWS02
- LLMNR hostname: ACMECT01

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
## 10.10.10.41 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.10.41` |
| MAC | `60:A5:E2:AE:32:1A` |
| Host ID | `60:a5:e2:ae:32:1a` |
| OUI Vendor | UNKNOWN |
| Hostname | ACMEWS02 |
| Vendor (CPE) | `microsoft` |
| Product (CPE) | `windows_10` |
| Device class (enum) | `workstation` |
| Pipelines fired | `3` |
| Processing path | `ENQUEUE_FUSION` |
| Triage routing | `ENQUEUE_FUSION` |
| Deterministic consensus | `— (—)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** *(not triggered)*

- **PIPELINE_3:** deterministic `—` (**LOW**)
```json
{
  "dhcp": [
    {
      "option12_hostname_hint": "ACMEWS02",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        119,
        121,
        249,
        252
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "discover",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x55ee0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 60:a5:e2:ae:32:1a\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Discover)\n\tLength: 1\n\tDHCP: Discover (1)\n\tHost Name: ACMEWS02\n\tVendor class identifier: MSFT 5.0\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 8\n\tLength: 8\n\tLength: 14\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (43) Vendor-Specific Information\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (119) Domain Search\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (252) Private/Proxy autodiscovery\n"
    },
    {
      "option12_hostname_hint": "ACMEWS02",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        119,
        121,
        249,
        252
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "request",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x55ee0002\n\tSeconds elapsed: 2\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 60:a5:e2:ae:32:1a\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Request)\n\tLength: 1\n\tDHCP: Request (3)\n\tHost Name: ACMEWS02\n\tVendor class identifier: MSFT 5.0\n\tRequested IP Address: 10.10.10.41\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (50) Requested IP Address (10.10.10.41)\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 8\n\tLength: 8\n\tLength: 4\n\tLength: 14\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (43) Vendor-Specific Information\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (119) Domain Search\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (252) Private/Proxy autodiscovery\n"
    }
  ],
  "deterministic_label": "",
  "deterministic_confidence": "LOW"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: ACMEWS02
- LLMNR hostname: ACMEWS02

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
## 10.10.20.1 — Likely benign / weak-signal endpoint (routing STAMP_LOW)

| Field | Value |
|-------|-------|
| IP | `10.10.20.1` |
| MAC | `00:1B:17:00:01:11` |
| Host ID | `00:1b:17:00:01:11` |
| OUI Vendor | Palo Alto Networks |
| Hostname | — |
| Vendor (CPE) | `paloaltonetworks` |
| Product (CPE) | `pan_os` |
| Device class (enum) | `firewall` |
| Pipelines fired | `pipeline_1` |
| Processing path | `STAMP_LOW` |
| Triage routing | `STAMP_LOW` |
| Deterministic consensus | `— (—)` |
| Confidence | **LOW** |
| Device Class | Likely benign / weak-signal endpoint (routing STAMP_LOW) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** *(not triggered)*

- **PIPELINE_3:** *(not triggered)*

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: —
- LLMNR hostname: —

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

> Single signal: single broadcast signal (type unknown). Insufficient for multi-signal classification without further capture.

---
## 10.10.20.7 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.20.7` |
| MAC | `00:50:56:8B:DC:01` |
| Host ID | `00:50:56:8b:dc:01` |
| OUI Vendor | VMware |
| Hostname | — |
| Vendor (CPE) | `vmware` |
| Product (CPE) | `—` |
| Device class (enum) | `—` |
| Pipelines fired | `3` |
| Processing path | `ENQUEUE_FUSION` |
| Triage routing | `ENQUEUE_FUSION` |
| Deterministic consensus | `— (—)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** *(not triggered)*

- **PIPELINE_3:** deterministic `—` (**LOW**)
```json
{
  "dhcp": [
    {
      "option12_hostname_hint": "MX700-bed12",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "offer",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0xaabbccdd\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.21\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:fb:bd:75:6d\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Offer)\n\tLength: 1\n\tDHCP: Offer (2)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: MX700-bed12\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 11\n"
    },
    {
      "option12_hostname_hint": "MX700-bed12",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        5,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,5,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "ack",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0xaabbccd0\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.21\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:fb:bd:75:6d\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (ACK)\n\tLength: 1\n\tDHCP: ACK (5)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: MX700-bed12\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 11\n"
    },
    {
      "option12_hostname_hint": "BRILL-CT01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "offer",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x33cc0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.30\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:90:20:aa:bb:01\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Offer)\n\tLength: 1\n\tDHCP: Offer (2)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: BRILL-CT01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 10\n"
    },
    {
      "option12_hostname_hint": "BRILL-CT01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        5,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,5,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "ack",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x33cc0002\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.30\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:90:20:aa:bb:01\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (ACK)\n\tLength: 1\n\tDHCP: ACK (5)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: BRILL-CT01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 10\n"
    },
    {
      "option12_hostname_hint": "ACMECT01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "offer",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x77aabb01\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.40\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: e8:d8:d1:aa:bb:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Offer)\n\tLength: 1\n\tDHCP: Offer (2)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: ACMECT01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 8\n"
    },
    {
      "option12_hostname_hint": "ACMECT01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        5,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,5,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "ack",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x77aabb02\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.40\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: e8:d8:d1:aa:bb:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (ACK)\n\tLength: 1\n\tDHCP: ACK (5)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: ACMECT01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 8\n"
    },
    {
      "option12_hostname_hint": "CCPLATFORM01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "offer",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x44dd0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.20.20\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:5c:bb:cc:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Offer)\n\tLength: 1\n\tDHCP: Offer (2)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: CCPLATFORM01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 12\n"
    },
    {
      "option12_hostname_hint": "CCPLATFORM01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        5,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,5,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "ack",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x44dd0002\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.20.20\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:5c:bb:cc:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (ACK)\n\tLength: 1\n\tDHCP: ACK (5)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: CCPLATFORM01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 12\n"
    },
    {
      "option12_hostname_hint": "ACMEWS02",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "offer",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x55ee0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.41\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 60:a5:e2:ae:32:1a\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Offer)\n\tLength: 1\n\tDHCP: Offer (2)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: ACMEWS02\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 8\n"
    },
    {
      "option12_hostname_hint": "ACMEWS02",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        5,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,5,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "ack",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x55ee0002\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.10.41\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 60:a5:e2:ae:32:1a\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (ACK)\n\tLength: 1\n\tDHCP: ACK (5)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: ACMEWS02\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 8\n"
    },
    {
      "option12_hostname_hint": "PACSARCH01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "offer",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x66ff0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.20.30\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:50:56:8b:ca:fe\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Offer)\n\tLength: 1\n\tDHCP: Offer (2)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: PACSARCH01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 10\n"
    },
    {
      "option12_hostname_hint": "PACSARCH01",
      "option60_vendor_class": "",
      "option55_ordered_guess": [
        1,
        2,
        3,
        5,
        6,
        12,
        51,
        53,
        54,
        58,
        59,
        255
      ],
      "option55_key_guess": "1,2,3,5,6,12,51,53,54,58,59,255",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "ack",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Reply (2)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x66ff0002\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 10.10.20.30\n\tNext server IP address: 10.10.20.7\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:50:56:8b:ca:fe\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (ACK)\n\tLength: 1\n\tDHCP: ACK (5)\n\tDHCP Server Identifier: 10.10.20.7\n\tIP Address Lease Time: 1 day (86400)\n\tRenewal Time Value: 12 hours (43200)\n\tRebinding Time Value: 21 hours (75600)\n\tSubnet Mask: 255.255.255.0\n\tRouter: 10.10.20.1\n\tDomain Name Server: 10.10.20.7\n\tHost Name: PACSARCH01\n\tOption End: 255\n\tOption: (54) DHCP Server Identifier (10.10.20.7)\n\tOption: (51) IP Address Lease Time\n\tOption: (58) Renewal Time Value\n\tOption: (59) Rebinding Time Value\n\tOption: (1) Subnet Mask (255.255.255.0)\n\tOption: (3) Router\n\tOption: (6) Domain Name Server\n\tOption: (12) Host Name\n\tOption: (255) End\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 4\n\tLength: 10\n"
    }
  ],
  "deterministic_label": "",
  "deterministic_confidence": "LOW"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: —
- LLMNR hostname: —

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
## 10.10.20.20 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.20.20` |
| MAC | `00:09:5C:BB:CC:02` |
| Host ID | `00:09:5c:bb:cc:02` |
| OUI Vendor | Philips Medical Systems - Cardiac and Monitoring |
| Hostname | CCPLATFORM01 |
| Vendor (CPE) | `microsoft` |
| Product (CPE) | `windows_10` |
| Device class (enum) | `workstation` |
| Pipelines fired | `3` |
| Processing path | `DETERMINISTIC_FINAL` |
| Triage routing | `DETERMINISTIC_FINAL` |
| Deterministic consensus | `Philips modality / DICOM-speaking device (HIGH)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** *(not triggered)*

- **PIPELINE_3:** deterministic `Philips modality / DICOM-speaking device` (**HIGH**)
```json
{
  "dicom_association": [
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "02",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [
          "1.3.46.670589.40.->Philips Clinical Collaboration Platform",
          "1.3.46.->Philips Healthcare"
        ],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "04",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [
          "1.2.840.113704."
        ],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    },
    {
      "dicom_association": {
        "pdu_type_byte": "",
        "implementation_class_uid": "",
        "implementation_version_name": "",
        "sop_class_hints": [],
        "philips_image_uid_arc_hits": [],
        "dicom_modality": "",
        "dicom_manufacturer": "",
        "dicom_manufacturer_model": "",
        "dicom_software_versions": ""
      }
    }
  ],
  "dhcp": [
    {
      "option12_hostname_hint": "CCPLATFORM01",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        119,
        121,
        249,
        252
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "discover",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x44dd0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:5c:bb:cc:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Discover)\n\tLength: 1\n\tDHCP: Discover (1)\n\tHost Name: CCPLATFORM01\n\tVendor class identifier: MSFT 5.0\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 12\n\tLength: 8\n\tLength: 14\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (43) Vendor-Specific Information\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (119) Domain Search\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (252) Private/Proxy autodiscovery\n"
    },
    {
      "option12_hostname_hint": "CCPLATFORM01",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        119,
        121,
        249,
        252
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "request",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x44dd0002\n\tSeconds elapsed: 2\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:09:5c:bb:cc:02\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Request)\n\tLength: 1\n\tDHCP: Request (3)\n\tHost Name: CCPLATFORM01\n\tVendor class identifier: MSFT 5.0\n\tRequested IP Address: 10.10.20.20\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (50) Requested IP Address (10.10.20.20)\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 12\n\tLength: 8\n\tLength: 4\n\tLength: 14\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (43) Vendor-Specific Information\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (119) Domain Search\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (252) Private/Proxy autodiscovery\n"
    }
  ],
  "deterministic_label": "Philips modality / DICOM-speaking device",
  "deterministic_confidence": "HIGH"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: CCPLATFORM01
- LLMNR hostname: CCPLATFORM01

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
## 10.10.20.30 — Unclassified (triage only)

| Field | Value |
|-------|-------|
| IP | `10.10.20.30` |
| MAC | `00:50:56:8B:CA:FE` |
| Host ID | `00:50:56:8b:ca:fe` |
| OUI Vendor | VMware |
| Hostname | PACSARCH01 |
| Vendor (CPE) | `microsoft` |
| Product (CPE) | `windows_server` |
| Device class (enum) | `server` |
| Pipelines fired | `2, 3` |
| Processing path | `ENQUEUE_FUSION` |
| Triage routing | `ENQUEUE_FUSION` |
| Deterministic consensus | `— (—)` |
| Confidence | **TRIAGE_ONLY** |
| Device Class | Unclassified (triage only) |

### Pipeline blocks (deterministic excerpts)

- **PIPELINE_1:** *(not triggered)*

- **PIPELINE_2:** deterministic `—` (**LOW**)
```json
{
  "smb2_negotiate": [
    {
      "dialects_sample": "",
      "dialect_revision": "",
      "signing_enabled": ""
    },
    {
      "dialects_sample": "",
      "dialect_revision": "",
      "signing_enabled": ""
    }
  ],
  "deterministic_label": "",
  "deterministic_confidence": "LOW"
}
```

- **PIPELINE_3:** deterministic `—` (**LOW**)
```json
{
  "dhcp": [
    {
      "option12_hostname_hint": "PACSARCH01",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        119,
        121,
        249,
        252
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "discover",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x66ff0001\n\tSeconds elapsed: 0\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:50:56:8b:ca:fe\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Discover)\n\tLength: 1\n\tDHCP: Discover (1)\n\tHost Name: PACSARCH01\n\tVendor class identifier: MSFT 5.0\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 10\n\tLength: 8\n\tLength: 14\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (43) Vendor-Specific Information\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (119) Domain Search\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (252) Private/Proxy autodiscovery\n"
    },
    {
      "option12_hostname_hint": "PACSARCH01",
      "option60_vendor_class": "MSFT 5.0",
      "option55_ordered_guess": [
        1,
        3,
        6,
        15,
        31,
        33,
        43,
        44,
        46,
        47,
        119,
        121,
        249,
        252
      ],
      "option55_key_guess": "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
      "fingerbank_dhcp_hit": "",
      "vendor_medical_hint": "",
      "dhcp_message_type": "request",
      "dhcp_text_excerpt": "Layer DHCP\n:\tMessage type: Boot Request (1)\n\tHardware type: Ethernet (0x01)\n\tHardware address length: 6\n\tHops: 0\n\tTransaction ID: 0x66ff0002\n\tSeconds elapsed: 2\n\tBootp flags: 0x0000 (Unicast)\n\t0... .... .... .... = Broadcast flag: Unicast\n\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP address: 0.0.0.0\n\tYour (client) IP address: 0.0.0.0\n\tNext server IP address: 0.0.0.0\n\tRelay agent IP address: 0.0.0.0\n\tClient MAC address: 00:50:56:8b:ca:fe\n\tClient hardware address padding: 00000000000000000000\n\tServer host name not given\n\tBoot file name not given\n\tMagic cookie: DHCP\n\tOption: (53) DHCP Message Type (Request)\n\tLength: 1\n\tDHCP: Request (3)\n\tHost Name: PACSARCH01\n\tVendor class identifier: MSFT 5.0\n\tRequested IP Address: 10.10.20.30\n\tParameter Request List Item: (1) Subnet Mask\n\tOption End: 255\n\tOption: (12) Host Name\n\tOption: (60) Vendor class identifier\n\tOption: (50) Requested IP Address (10.10.20.30)\n\tOption: (55) Parameter Request List\n\tOption: (255) End\n\tLength: 10\n\tLength: 8\n\tLength: 4\n\tLength: 14\n\tParameter Request List Item: (3) Router\n\tParameter Request List Item: (6) Domain Name Server\n\tParameter Request List Item: (15) Domain Name\n\tParameter Request List Item: (31) Perform Router Discover\n\tParameter Request List Item: (33) Static Route\n\tParameter Request List Item: (43) Vendor-Specific Information\n\tParameter Request List Item: (44) NetBIOS over TCP/IP Name Server\n\tParameter Request List Item: (46) NetBIOS over TCP/IP Node Type\n\tParameter Request List Item: (47) NetBIOS over TCP/IP Scope\n\tParameter Request List Item: (119) Domain Search\n\tParameter Request List Item: (121) Classless Static Route\n\tParameter Request List Item: (249) Private/Classless Static Route (Microsoft)\n\tParameter Request List Item: (252) Private/Proxy autodiscovery\n"
    }
  ],
  "deterministic_label": "",
  "deterministic_confidence": "LOW"
}
```

### Broadcast / legacy flat summary

- SSDP hints: `[]` …
- WS-Discovery UUID: `—`
- WS-Discovery Types: —
- mDNS hostname: —
- mDNS TXT: —
- DNS-SD services: —
- LLMNR queries: PACSARCH01
- LLMNR hostname: PACSARCH01

**Contradictions (deterministic codes):**
None

**Expert Anomalies:** None

---
