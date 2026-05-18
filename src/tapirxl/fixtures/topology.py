"""Network topology constants for the synthetic Philips demo PCAP.

This module contains only pure-Python constants (strings, ints, dicts).
No external imports — builder.py carries all scapy/pydicom/pynetdicom usage.
"""

from __future__ import annotations

DOMAIN_NAME = "ACMEHOSP"

# ── Clinical VLAN 10.10.10.0/24 ──────────────────────────────────────────────

INTELLIVUE = {
    "name": "MX700-bed12",
    "mac": "00:09:fb:bd:75:6d",
    "ip": "10.10.10.21",
}

BRILLIANCE = {
    "name": "BRILL-CT01",
    "mac": "00:90:20:aa:bb:01",
    "ip": "10.10.10.30",
}

WIN7_CONSOLE = {
    "name": "ACMECT01",
    "mac": "e8:d8:d1:aa:bb:02",
    "ip": "10.10.10.40",
}

ACMEWS02 = {
    "name": "ACMEWS02",
    "mac": "60:a5:e2:ae:32:1a",
    "ip": "10.10.10.41",
}
DO_PEER = ACMEWS02  # backwards-compatible alias

# ── IT / Management VLAN 10.10.20.0/24 ───────────────────────────────────────

CCPLATFORM = {
    "name": "CCPLATFORM01",
    "mac": "00:09:5c:bb:cc:02",
    "ip": "10.10.20.20",
}

PACSARCH01 = {
    "name": "PACSARCH01",
    "mac": "00:50:56:8b:ca:fe",
    "ip": "10.10.20.30",
}
PACS_SERVER = PACSARCH01  # backwards-compatible alias

DHCP_SERVER = {
    "name": "DHCP01",
    "mac": "00:50:56:8b:dc:01",
    "ip": "10.10.20.7",
}

GATEWAY = {
    "name": None,
    "mac": "00:1b:17:00:01:11",
    "ip": "10.10.20.1",
}

# External TLS destinations reached via GATEWAY's MAC.
TLS_SENTINELONE = {"mac": GATEWAY["mac"], "ip": "52.94.231.50"}
TLS_MICROSOFT = {"mac": GATEWAY["mac"], "ip": "20.42.65.92"}

# ── Protocol constants ────────────────────────────────────────────────────────

DICOM_TCP_PORT = 104

BRILLIANCE_IMPL_UID = "1.3.46.670589.30.36.0"
BRILLIANCE_IMPL_VER = "PMS_ELEVA_416"
CCPLATFORM_IMPL_UID = "1.3.46.670589.40.12.2.1"
CCPLATFORM_IMPL_VER = "PMS_ELEVA_CCP12"

CALLING_CT_AE_TITLE = "CT9999999"
CALLED_CC_AE_TITLE = "CCPLATFORM"

CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"
SOP_INSTANCE_UID_STR = "1.2.840.113704.1.7.1.0.1234567890.1"

WS_DISCOVERY_UUID = "50484248-4332-3638-3631-0009fbbd756d"
WS_TYPES = ["urn:ihe-pcd:device:patientmonitor"]

DHCP_OPTIONS_PRL = [1, 3, 6, 15, 28, 51, 58, 59]
WIN7_DHCP_PRL = [1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43]
WIN10_DHCP_PRL = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]

TLS_HTTPS_PORT = 443

DICOM_MESSAGE_ID = 1337
MAXIMUM_PDV_LENGTH_BYTES = 16382

# ── Synthesis anchors (CVE/CPE documentary mapping) ──────────────────────────

SYNTHESIS_ANCHORS: dict[str, dict] = {
    INTELLIVUE["mac"]: {
        "cve": "CVE-2020-16216",
        "cpe": "cpe:2.3:h:philips:intellivue_mx700:-:*:*:*:*:*:*:*",
        "signals": ["WS-Discovery BH series UUID", "DHCP option 60"],
    },
    BRILLIANCE["mac"]: {
        "cve": "CVE-2018-8857",
        "cpe": "cpe:2.3:h:philips:brilliance_ict:-:*:*:*:*:*:*:*",
        "signals": [
            "A-ASSOCIATE-RQ Philips impl UID",
            "C-STORE SoftwareVersions dataset",
        ],
    },
    CCPLATFORM["mac"]: {
        "cve": "CVE-2020-16247",
        "cpe": "cpe:2.3:a:philips:clinical_collaboration_platform:12.2.1:*:*:*:*:*:*:*",
        "signals": ["A-ASSOCIATE-AC responder identity strings"],
    },
    WIN7_CONSOLE["mac"]: {
        "cve": "CVE-2021-1675",
        "cpe": "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*:*",
        "signals": [
            "DHCP Option 60 'MSFT 5.0' + Option 55 PRL Win7 default",
            "SMB2 Negotiate dialects 0x0202 + 0x0210",
            "TLS ClientHello SNI usea1-016.sentinelone.net",
            "TLS ClientHello SNI events.data.microsoft.com",
            "LLMNR query DC2.acme.local (unanswered)",
        ],
    },
}
