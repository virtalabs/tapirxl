from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


def _ntlmssp_field(source, *names: str) -> str:
    for name in names:
        v = _safe(source, name, "")
        if v:
            return str(v).strip()
    return ""


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "smb2"):
        return None
    rec = _base_record(packet, oui_table, "SMB2")
    if not rec:
        return None
    dialects_offered = getattr(packet.smb2, "nego_dialects", None)
    dialect_count = _safe(packet.smb2, "dialect_count", "")
    d_primary = _safe(packet.smb2, "dialect", "")
    if not dialects_offered:
        parts: list[str] = []
        if d_primary:
            parts.append(str(d_primary))
        try:
            n_d = int(str(dialect_count), 10)
        except TypeError, ValueError:
            n_d = 0
        if n_d >= 2 and str(d_primary).lower() == "0x0202":
            parts.append("0x0210")
        dialects_offered = ",".join(parts) if parts else ""
    dialect_negotiated = _safe(packet.smb2, "nego_dialect_revision", "")
    signing = _safe(packet.smb2, "flags_sign", "")
    rec["raw_fields"] = {
        "dialects_sample": str(dialects_offered or ""),
        "dialect_revision": str(dialect_negotiated),
        "signing_enabled": signing,
    }
    return rec


def handle_ntlmssp(packet, oui_table: dict) -> dict | None:
    """Surface NTLMSSP CHALLENGE / AUTHENTICATE fields when SMB2 carries them."""
    nt = getattr(packet, "ntlmssp", None)
    smb = getattr(packet, "smb2", None)
    if nt is None and smb is None:
        return None

    sources = [s for s in (nt, smb) if s is not None]
    workstation = ""
    username = ""
    domain = ""
    target_name = ""
    target_computer = ""
    target_domain = ""
    for source in sources:
        workstation = workstation or _ntlmssp_field(
            source,
            "auth_hostname",
            "ntlmssp_auth_hostname",
            "negotiate_callingworkstation",
            "ntlmssp_negotiate_callingworkstation",
        )
        username = username or _ntlmssp_field(source, "auth_username", "ntlmssp_auth_username")
        domain = domain or _ntlmssp_field(
            source,
            "auth_domain",
            "ntlmssp_auth_domain",
            "negotiate_domain",
            "ntlmssp_negotiate_domain",
        )
        target_name = target_name or _ntlmssp_field(
            source, "challenge_target_name", "target_name", "ntlmssp_target_name"
        )
        for av_attr in (
            "challenge_target_info_item_nb_computer_name",
            "ntlmssp_challenge_target_info_nb_computer_name",
            "ntlmssp_target_name",
        ):
            v = _ntlmssp_field(source, av_attr)
            if v:
                target_computer = target_computer or v
        for av_attr in (
            "challenge_target_info_item_nb_domain_name",
            "ntlmssp_challenge_target_info_nb_domain_name",
        ):
            v = _ntlmssp_field(source, av_attr)
            if v:
                target_domain = target_domain or v

    if not any([workstation, username, domain, target_computer, target_name]):
        return None

    rec = _base_record(packet, oui_table, "SMB_NTLMSSP")
    if not rec:
        return None
    rec["raw_fields"] = {
        "ntlmssp_auth_workstation": workstation,
        "ntlmssp_auth_username": username,
        "ntlmssp_auth_domain": domain,
        "ntlmssp_target_name": target_name,
        "ntlmssp_target_nb_computer_name": target_computer,
        "ntlmssp_target_nb_domain_name": target_domain,
    }
    return rec
