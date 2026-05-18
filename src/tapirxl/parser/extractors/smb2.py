from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


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
        except (TypeError, ValueError):
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
    if not hasattr(packet, "ntlmssp"):
        return None
    nt = packet.ntlmssp

    workstation = _safe(nt, "auth_hostname", "") or _safe(nt, "ntlmssp_auth_hostname", "") or ""
    username = _safe(nt, "auth_username", "") or _safe(nt, "ntlmssp_auth_username", "") or ""
    domain = _safe(nt, "auth_domain", "") or _safe(nt, "ntlmssp_auth_domain", "") or ""
    target_name = _safe(nt, "challenge_target_name", "") or _safe(nt, "target_name", "") or ""

    target_computer = ""
    for av_attr in (
        "challenge_target_info_item_nb_computer_name",
        "ntlmssp_challenge_target_info_nb_computer_name",
        "ntlmssp_target_name",
    ):
        v = _safe(nt, av_attr, "")
        if v:
            target_computer = v
            break
    target_domain = ""
    for av_attr in (
        "challenge_target_info_item_nb_domain_name",
        "ntlmssp_challenge_target_info_nb_domain_name",
    ):
        v = _safe(nt, av_attr, "")
        if v:
            target_domain = v
            break

    if not any([workstation, username, domain, target_computer, target_name]):
        return None

    rec = _base_record(packet, oui_table, "SMB_NTLMSSP")
    if not rec:
        return None
    rec["raw_fields"] = {
        "ntlmssp_auth_workstation": str(workstation).strip(),
        "ntlmssp_auth_username": str(username).strip(),
        "ntlmssp_auth_domain": str(domain).strip(),
        "ntlmssp_target_name": str(target_name).strip(),
        "ntlmssp_target_nb_computer_name": str(target_computer).strip(),
        "ntlmssp_target_nb_domain_name": str(target_domain).strip(),
    }
    return rec
