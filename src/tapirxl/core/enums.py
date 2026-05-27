"""CPE-aligned vendor/product/device-class enums and deterministic mappers.

No project imports. Enums are intentionally limited to vendors and products
observed in the synthetic + Schoolcraft PCAPs. Slugs match cpe:2.3 slots 3/4.
"""

from __future__ import annotations

# ── Enum tuples (used for validation in _enum_or_none) ────────────────────────

CPE_VENDOR_ENUM: tuple[str, ...] = (
    "microsoft",
    "philips",
    "gehealthcare",
    "vmware",
    "paloaltonetworks",
    "intel",
)

CPE_PRODUCT_ENUM: tuple[str, ...] = (
    "windows_7",
    "windows_10",
    "windows_server",
    "intellivue_mx700",
    "brilliance_ict",
    "brightspeed_elite_select",
    "clinical_collaboration_platform",
    "centricity_pacs_iw",
    "pan_os",
)

DEVICE_CLASS_ENUM: tuple[str, ...] = (
    # DICOM Modality (0008,0060) values:
    "CT",
    "MR",
    "US",
    "CR",
    "DX",
    "MG",
    "NM",
    "PT",
    # role / function classes:
    "patient_monitor",
    "clinical_workstation",
    "workstation",
    "server",
    "pacs",
    "firewall",
    "dhcp_server",
)

# OUI vendor substrings → CPE vendor slug (case-insensitive substring match)
CPE_VENDOR_OUI_MAP: list[tuple[str, str]] = [
    ("philips", "philips"),
    ("vmware", "vmware"),
    ("palo alto", "paloaltonetworks"),
    ("intel", "intel"),
    ("microsoft", "microsoft"),
    ("hyper-v", "microsoft"),
]

DICOM_MODALITY_ENUM: frozenset[str] = frozenset({"CT", "MR", "US", "CR", "DX", "MG", "NM", "PT"})


# ── Envelope helper accessors (pure dict → value) ─────────────────────────────


def _env_dhcp_records(env: dict) -> list[dict]:
    return (env.get("pipeline_3") or {}).get("dhcp") or []


def _env_dicom_assoc_results(env: dict) -> list[dict]:
    return (env.get("pipeline_3") or {}).get("dicom_association") or []


def _dicom_assoc_payload(raw: dict) -> dict:
    """Unwrap runtime ``{"dicom_association": {...}}`` envelope records."""
    inner = raw.get("dicom_association")
    return inner if isinstance(inner, dict) else raw


def _dicom_assoc_tags(raw: dict) -> dict:
    payload = _dicom_assoc_payload(raw)
    tags = raw.get("tags") or payload.get("tags") or {}
    return tags if isinstance(tags, dict) else {}


def _env_dhcp_vci(env: dict) -> str:
    for rec in _env_dhcp_records(env):
        vci = rec.get("option60_vendor_class") or ""
        if vci:
            return vci
    # Fallback: legacy flat key used by the monolith
    return env.get("dhcp_vendor_class") or ""


def _env_has_ntlmssp(env: dict) -> bool:
    p2 = env.get("pipeline_2") or {}
    smb2 = p2.get("smb2") or {}
    ntlmssp = smb2.get("ntlmssp") or {}
    return bool(
        ntlmssp.get("target_computer")
        or ntlmssp.get("workstation")
        # Legacy flat keys (monolith v1/v2)
        or env.get("ntlmssp_workstation")
        or env.get("ntlmssp_target_computer")
    )


def _env_has_sni_substring(env: dict, needle: str) -> bool:
    p2 = env.get("pipeline_2") or {}
    tls = p2.get("tls_sni") or {}
    domains = tls.get("sni_domains") or []
    for d in domains:
        if needle in str(d).lower():
            return True
    # Legacy flat key
    for hit in env.get("tls_sni_hints") or []:
        if needle in str(hit).lower():
            return True
    return False


# ── Deterministic field mappers ────────────────────────────────────────────────


def to_cpe_vendor(env: dict) -> str | None:
    """Map envelope to a CPE vendor slug (highest-priority signal first)."""
    promoted_man = (env.get("dicom_manufacturer") or "").lower()
    if "philips" in promoted_man:
        return "philips"
    if "ge healthcare" in promoted_man or promoted_man == "ge":
        return "gehealthcare"

    for assoc in _env_dicom_assoc_results(env):
        payload = _dicom_assoc_payload(assoc)
        tags = _dicom_assoc_tags(assoc)
        man = (
            payload.get("dicom_manufacturer")
            or tags.get("manufacturer")
            or tags.get("(0008,0070)")
            or ""
        ).lower()
        if "philips" in man:
            return "philips"
        if "ge healthcare" in man or man == "ge":
            return "gehealthcare"
        uid = (payload.get("implementation_class_uid") or "").lower()
        if uid.startswith("1.2.840.113619."):
            return "gehealthcare"
        if uid.startswith("1.3.46."):
            return "philips"
        if payload.get("philips_image_uid_arc_hits") or payload.get("image_uid_arc_counts", {}).get(
            "1.2.840.113704."
        ):
            return "philips"

    # Legacy flat keys (monolith)
    for assoc in env.get("dicom_assoc_results") or []:
        man = (assoc.get("dicom_manufacturer") or "").lower()
        if "philips" in man:
            return "philips"
        uid = (assoc.get("implementation_class_uid") or "").lower()
        if uid.startswith("1.3.46."):
            return "philips"
        if assoc.get("philips_image_uid_arc_hits"):
            return "philips"

    ws_pfx = (
        env.get("ws_vendor_prefix")
        or (env.get("pipeline_1") or {}).get("ws_discovery", {}).get("vendor_prefix_ascii")
        or ""
    ).lower()
    if "ph" in ws_pfx or "philips" in ws_pfx:
        return "philips"

    vci = _env_dhcp_vci(env).lower()
    if "philips" in vci:
        return "philips"
    if "msft" in vci or "microsoft" in vci:
        return "microsoft"

    oui = (env.get("oui_vendor") or "").lower()
    for needle, slug in CPE_VENDOR_OUI_MAP:
        if needle in oui:
            return slug

    return None


def to_cpe_product(env: dict) -> str | None:
    """Map envelope to a CPE product slug."""
    all_assoc = _env_dicom_assoc_results(env) or (env.get("dicom_assoc_results") or [])
    for assoc in all_assoc:
        payload = _dicom_assoc_payload(assoc)
        tags = _dicom_assoc_tags(assoc)
        model = (
            payload.get("dicom_manufacturer_model")
            or tags.get("model_name")
            or tags.get("(0008,1090)")
            or ""
        ).lower()
        if "brilliance ict" in model or "brilliance" in model:
            return "brilliance_ict"
        if "brightspeed" in model:
            return "brightspeed_elite_select"
        impl_uid = (payload.get("implementation_class_uid") or "").lower()
        if impl_uid.startswith("1.2.840.113619.7."):
            return "centricity_pacs_iw"
        if impl_uid.startswith("1.3.46.670589.40"):
            return "clinical_collaboration_platform"
        if impl_uid.startswith("1.3.46.670589.30"):
            return "brilliance_ict"

    vci = _env_dhcp_vci(env)
    fb_hits = [r.get("fingerbank_dhcp_hit") or "" for r in _env_dhcp_records(env)]

    if "MSFT 5.0" in vci:
        for fb in fb_hits:
            if "Windows 7" in fb or "Server 2008 R2" in fb:
                return "windows_7"
        oui = (env.get("oui_vendor") or "").lower()
        if "vmware" in oui or oui.startswith("hyper-v"):
            return "windows_server"
        return "windows_10"

    ws_series = env.get("ws_series_code") or (
        (env.get("pipeline_1") or {}).get("ws_discovery", {}).get("series_code_ascii")
    )
    if ws_series == "BH":
        return "intellivue_mx700"

    vci_l = vci.lower()
    if "brilliance" in vci_l:
        return "brilliance_ict"
    if "intellivue" in vci_l or "philips intellivue" in vci_l:
        return "intellivue_mx700"
    if "philips" in vci_l:
        return "intellivue_mx700"

    if (env.get("oui_vendor") or "").lower().startswith("palo alto"):
        return "pan_os"

    return None


def to_device_class(env: dict) -> str | None:
    """Map envelope to a device_class string (DICOM Modality wins)."""
    promoted_modality = (env.get("dicom_modality") or "").strip().upper()
    if promoted_modality in DICOM_MODALITY_ENUM:
        return promoted_modality

    all_assoc = _env_dicom_assoc_results(env) or (env.get("dicom_assoc_results") or [])
    for assoc in all_assoc:
        payload = _dicom_assoc_payload(assoc)
        tags = _dicom_assoc_tags(assoc)
        modality = (
            (payload.get("dicom_modality") or tags.get("modality") or tags.get("(0008,0060)") or "")
            .strip()
            .upper()
        )
        if modality in DICOM_MODALITY_ENUM:
            return modality

    ws_series = env.get("ws_series_code") or (
        (env.get("pipeline_1") or {}).get("ws_discovery", {}).get("series_code_ascii")
    )
    if ws_series in ("BH", "BV", "GD"):
        return "patient_monitor"

    vci = _env_dhcp_vci(env).lower()
    if "philips intellivue" in vci:
        return "patient_monitor"

    has_msft = "msft" in vci
    has_ntlmssp = _env_has_ntlmssp(env)
    has_sentinelone = _env_has_sni_substring(env, "sentinelone")
    has_dicom = bool(all_assoc)

    if has_msft and (has_sentinelone or (has_ntlmssp and (has_sentinelone or has_dicom))):
        return "clinical_workstation"

    if has_dicom and not (env.get("ws_uuid") or (env.get("pipeline_1") or {}).get("ws_discovery")):
        for assoc in all_assoc:
            payload = _dicom_assoc_payload(assoc)
            pdu_byte = (payload.get("pdu_type_byte") or assoc.get("pdu_type_byte") or "").lower()
            if pdu_byte == "02":
                return "pacs"

    oui = (env.get("oui_vendor") or "").lower()
    if "palo alto" in oui:
        return "firewall"

    if has_msft and has_ntlmssp:
        return "workstation"

    if has_msft and ("vmware" in oui or oui.startswith("hyper-v")):
        return "server"

    llmnr_name = env.get("llmnr_hostname") or (
        (env.get("pipeline_1") or {}).get("llmnr", {}).get("claimed_hostname")
    )
    if has_msft and llmnr_name:
        return "workstation"

    return None


def enum_or_none(value: str | None, allowed: tuple[str, ...]) -> str | None:
    if not value:
        return None
    return value if value in allowed else None
