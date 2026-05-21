"""Merge raw extraction records into per-MAC HostEnvelope dicts."""

from __future__ import annotations

from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import oui_lookup
from tapirxl.parser.tables import (
    CLINICAL_SERVICE_STRINGS,
    DHCP_VENDOR_CLASS_MEDICAL,
    KNOWN_MEDICAL_UUID_PREFIXES,
    PHILIPS_INTELLIVUE_SERIES,
)


def ensure_pipeline(envelope: dict, name: str) -> dict:
    if envelope.get(name) is None:
        envelope[name] = {}
    return envelope[name]


def make_empty_envelope(mac: str, oui_table: dict) -> dict:
    mac_n = normalize_mac(mac)
    return {
        "host_id": mac_n.lower(),
        "mac": mac_n,
        "ip": "",
        "ip_observations": [],
        "oui_vendor": oui_lookup(mac_n, oui_table),
        "ws_uuid": None,
        "ws_vendor_prefix": None,
        "ws_series_code": None,
        "ws_series_family": None,
        "ws_types": [],
        "ws_scopes": [],
        "mdns_hostname": None,
        "mdns_txt_raw": [],
        "mdns_txt_parsed": {},
        "dns_sd_services": [],
        "llmnr_queries": [],
        "llmnr_hostname": None,
        "ssdp_observations": [],
        "arp_bindings": [],
        "capsule_mdip": {},
        "dhcp_hostname": None,
        "ntlmssp_workstation": None,
        "ntlmssp_domain": None,
        "ntlmssp_username": None,
        "ntlmssp_target_computer": None,
        "dicom_modality": None,
        "dicom_manufacturer": None,
        "dicom_manufacturer_model": None,
        "expert_flags": [],
        "signal_count": 0,
        "floor_triggers": [],
        "contradictions": [],
        "triage": {
            "routing": None,
            "deterministic_consensus": None,
            "pipelines_fired": [],
            "contradiction_codes": [],
        },
        "lm_envelope": {"ambiguous_fields": []},
        "pipeline_1": None,
        "pipeline_2": None,
        "pipeline_3": None,
    }


def finalize_envelope_timestamps(envelope: dict) -> None:
    ts_all = envelope.pop("_pkt_ts", [])
    envelope.pop("_seen_ts", None)
    if ts_all:
        new_first = min(ts_all)
        new_last = max(ts_all)
        if "first_seen_ts" in envelope:
            envelope["first_seen_ts"] = min(envelope["first_seen_ts"], new_first)
        else:
            envelope["first_seen_ts"] = new_first
        if "last_seen_ts" in envelope:
            envelope["last_seen_ts"] = max(envelope["last_seen_ts"], new_last)
        else:
            envelope["last_seen_ts"] = new_last


def _uniq_append(env: dict, lst_key: str, value: object) -> None:
    if value is None or value == "":
        return
    bucket = env.setdefault(lst_key, [])
    if value not in bucket:
        bucket.append(value)


def merge_record_into_envelope(env: dict, rec: dict) -> None:
    """Destructively merge a Layer-1 extraction record into the envelope (per-MAC)."""
    env.setdefault("_pkt_ts", []).append(float(rec.get("timestamp", 0)))
    ips = env.setdefault("ip_observations", [])
    sip = rec.get("src_ip")
    if sip and sip != "0.0.0.0" and sip not in ips:
        ips.append(sip)
    if rec.get("src_oui") and rec["src_oui"] != "UNKNOWN":
        env["oui_vendor"] = rec["src_oui"]

    proto = rec["protocol"]
    rf = rec.get("raw_fields", {})

    if rec.get("expert_flag") and rec.get("expert_message"):
        msg = rec["expert_message"]
        if msg not in env["expert_flags"]:
            env["expert_flags"].append(msg)

    if proto == "WS_DISCOVERY":
        if rf.get("ws_uuid") and not env["ws_uuid"]:
            env["ws_uuid"] = rf["ws_uuid"]
            env["ws_vendor_prefix"] = rf.get("ws_vendor_prefix")
            env["ws_series_code"] = rf.get("ws_series_code")
        for t in rf.get("ws_types", []) or []:
            if t not in env["ws_types"]:
                env["ws_types"].append(t)
        for s in rf.get("ws_scopes", []) or []:
            if s not in env["ws_scopes"]:
                env["ws_scopes"].append(s)
        p1 = ensure_pipeline(env, "pipeline_1")
        p1.setdefault("ws_discovery_seen", True)

    elif proto == "MDNS_A":
        if rf.get("mdns_hostname") and not env["mdns_hostname"]:
            env["mdns_hostname"] = rf["mdns_hostname"]
        ensure_pipeline(env, "pipeline_1")

    elif proto == "MDNS_TXT":
        for entry in rf.get("mdns_txt_raw", []) or []:
            if entry not in env["mdns_txt_raw"]:
                env["mdns_txt_raw"].append(entry)
        env["mdns_txt_parsed"].update(rf.get("mdns_txt_parsed") or {})
        if rf.get("resp_name") and not env["mdns_hostname"]:
            env["mdns_hostname"] = rf["resp_name"]
        ensure_pipeline(env, "pipeline_1")

    elif proto == "DNS_SD_PTR":
        svc = rf.get("ptr_domain_name", "")
        if svc and svc not in env["dns_sd_services"]:
            env["dns_sd_services"].append(svc)
        ensure_pipeline(env, "pipeline_1")

    elif proto == "LLMNR":
        qn = rf.get("query_name")
        rn = rf.get("resp_name")
        if qn and qn not in env["llmnr_queries"]:
            env["llmnr_queries"].append(qn)
        if rn and not env["llmnr_hostname"]:
            env["llmnr_hostname"] = rn
        ensure_pipeline(env, "pipeline_1")

    elif proto == "SSDP":
        ensure_pipeline(env, "pipeline_1")
        env.setdefault("ssdp_observations", []).append(
            {
                "server": rf.get("server"),
                "usn": rf.get("usn"),
                "hints": rf.get("device_hints", []),
            }
        )

    elif proto == "CAPSULE_MDIP":
        ensure_pipeline(env, "pipeline_1")
        env["capsule_mdip"].setdefault("tokens", []).append(rf.get("capsule_token"))
        env["capsule_mdip"]["udp5090"] = rf.get("mdip_udp5090_seen")
        env["capsule_mdip"]["tls"] = rf.get("mdip_tcp_tls")

    elif proto == "ARP":
        ensure_pipeline(env, "pipeline_1")
        env.setdefault("arp_bindings", []).append(rf)

    elif proto == "TCP_SYN":
        p2 = ensure_pipeline(env, "pipeline_2")
        p2.setdefault("syn_fingerprints", []).append(rf)

    elif proto == "TLS_SNI":
        p2 = ensure_pipeline(env, "pipeline_2")
        p2.setdefault("sni_hits", []).append(rf)

    elif proto == "SMB2":
        p2 = ensure_pipeline(env, "pipeline_2")
        p2.setdefault("smb2_negotiate", []).append(rf)

    elif proto == "SMB_NTLMSSP":
        p2 = ensure_pipeline(env, "pipeline_2")
        p2.setdefault("ntlmssp", []).append(rf)
        ws = (rf.get("ntlmssp_auth_workstation") or "").strip()
        dom = (rf.get("ntlmssp_auth_domain") or "").strip()
        usr = (rf.get("ntlmssp_auth_username") or "").strip()
        tgt = (
            rf.get("ntlmssp_target_nb_computer_name") or rf.get("ntlmssp_target_name") or ""
        ).strip()
        if ws and not env.get("ntlmssp_workstation"):
            env["ntlmssp_workstation"] = ws
        if dom and not env.get("ntlmssp_domain"):
            env["ntlmssp_domain"] = dom
        if usr and not env.get("ntlmssp_username"):
            env["ntlmssp_username"] = usr
        if tgt and not env.get("ntlmssp_target_computer"):
            env["ntlmssp_target_computer"] = tgt

    elif proto == "KERBEROS":
        p2 = ensure_pipeline(env, "pipeline_2")
        p2.setdefault("kerberos", []).append(rf)

    elif proto == "DNS_LOOKUP":
        p2 = ensure_pipeline(env, "pipeline_2")
        p2.setdefault("dns_lookups", []).append(rf)

    elif proto == "SSH":
        ensure_pipeline(env, "pipeline_2")
        _uniq_append(env, "_ssh_banners", rf.get("banner"))

    elif proto == "DICOM":
        p3 = ensure_pipeline(env, "pipeline_3")
        p3.setdefault("dicom_association", []).append(rf)
        assoc = rf.get("dicom_association") or {}
        for env_key, assoc_key in (
            ("dicom_modality", "dicom_modality"),
            ("dicom_manufacturer", "dicom_manufacturer"),
            ("dicom_manufacturer_model", "dicom_manufacturer_model"),
        ):
            v = (assoc.get(assoc_key) or "").strip()
            if v and not env.get(env_key):
                env[env_key] = v

    elif proto == "DHCP":
        p3 = ensure_pipeline(env, "pipeline_3")
        p3.setdefault("dhcp", []).append(rf)
        msg_t = (rf.get("dhcp_message_type") or "").lower()
        if msg_t in ("discover", "request", ""):
            h = (rf.get("option12_hostname_hint") or "").strip()
            if h and not env.get("dhcp_hostname"):
                env["dhcp_hostname"] = h

    elif proto == "SNMP":
        p3 = ensure_pipeline(env, "pipeline_3")
        p3.setdefault("snmp_sysdescr", []).append(rf)

    elif proto == "HL7_MLLP":
        p3 = ensure_pipeline(env, "pipeline_3")
        p3.setdefault("hl7_segments", []).append(rf)


def finalize_envelope_from_records(env: dict) -> dict:
    """Compute rollups after merging all records for a host."""
    finalize_envelope_timestamps(env)

    macs_obs = []
    if env["mac"]:
        macs_obs.append(env["mac"])
    for bn in env.get("arp_bindings", []) or []:
        if bn.get("sha"):
            macs_obs.append(normalize_mac(bn["sha"]))

    if env["ws_series_code"]:
        env["ws_series_family"] = PHILIPS_INTELLIVUE_SERIES.get(env["ws_series_code"])

    has_ws = bool(env["ws_uuid"])
    has_mdns = bool(env["mdns_hostname"] or env["mdns_txt_raw"] or env["mdns_txt_parsed"])
    has_dns_sd = bool(env["dns_sd_services"])
    has_llmnr = bool(env["llmnr_queries"] or env["llmnr_hostname"])

    pipelines_fired: list[int] = []
    if env.get("pipeline_1"):
        pipelines_fired.append(1)
    if env.get("pipeline_2"):
        pipelines_fired.append(2)
    if env.get("pipeline_3"):
        pipelines_fired.append(3)
    env["triage"]["pipelines_fired"] = pipelines_fired

    buckets = []
    buckets.append(has_ws)
    buckets.append(has_mdns or has_dns_sd or has_llmnr)
    buckets.append(any(env.get("ssdp_observations", [])))
    buckets.append(any(env.get("arp_bindings", [])))
    buckets.append(bool(env.get("capsule_mdip", {}).get("tokens")))
    if env.get("pipeline_2"):
        buckets.append(True)
    if env.get("pipeline_3"):
        buckets.append(True)
    env["signal_count"] = sum(bool(b) for b in buckets)

    env["floor_triggers"] = []
    # Spec floor triggers (CLAUDE.md §6.2).
    if env.get("ws_vendor_prefix") in KNOWN_MEDICAL_UUID_PREFIXES:
        env["floor_triggers"].append("MEDICAL_UUID_PREFIX")
    if any(cs in svc for svc in env["dns_sd_services"] for cs in CLINICAL_SERVICE_STRINGS):
        env["floor_triggers"].append("CLINICAL_SERVICE")
    if env["expert_flags"]:
        env["floor_triggers"].append("EXPERT_ANOMALY")

    p3 = env.get("pipeline_3") or {}
    p3_dicom = p3.get("dicom_association") or []
    if any((da.get("dicom_association") or {}).get("sop_class_hints") for da in p3_dicom):
        env["floor_triggers"].append("DICOM_VENDOR_ARC")
    if any(
        (da.get("dicom_association") or {}).get("philips_image_uid_arc_hits") for da in p3_dicom
    ):
        env["floor_triggers"].append("DICOM_PHILIPS_IMAGE_UID")

    p3_dhcp = p3.get("dhcp") or []
    if any((dh.get("vendor_medical_hint") or "").strip() for dh in p3_dhcp):
        env["floor_triggers"].append("DHCP_MEDICAL_VENDOR_CLASS")

    # The HL7 extractor only fires on \x0b-framed MLLP, so the presence of any
    # hl7_segments entry is equivalent to hl7.mllp_detected == True.
    if p3.get("hl7_segments"):
        env["floor_triggers"].append("HL7_CLINICAL_INTERFACE")

    # Symmetric with DHCP_MEDICAL_VENDOR_CLASS: scan raw sysDescr against the
    # medical-vendor substring list rather than relying on the deterministic
    # label containing a particular word.
    p3_snmp = p3.get("snmp_sysdescr") or []
    if any(
        any(
            sub.lower() in (sn.get("sys_descr") or "").lower()
            for sub, _lbl in DHCP_VENDOR_CLASS_MEDICAL
        )
        for sn in p3_snmp
    ):
        env["floor_triggers"].append("SNMP_MEDICAL_SYSDESCR")

    # Documented extensions outside the spec — preserved because they drive
    # deterministic labeling for media devices. Removing the now-redundant
    # CLINICAL_APP_PROTO trigger (any pipeline_3 record) since DICOM/DHCP/HL7
    # /SNMP triggers above cover its semantics with finer granularity.
    for obs in env.get("ssdp_observations", []) or []:
        for h in obs.get("hints") or []:
            if "Sonos" in h:
                env["floor_triggers"].append("SSDP_MEDIA_CLOUD")
                break
        if "- Sonos networked" not in "".join(env.get("floor_triggers", [])) and obs.get("hints"):
            env["floor_triggers"].append("SSDP_METADATA")
            break

    ips_clean = [i for i in env["ip_observations"] if i and i != "0.0.0.0"]
    env["ip"] = (
        ips_clean[0]
        if ips_clean
        else (env["ip_observations"][0] if env["ip_observations"] else "0.0.0.0")
    )

    env.pop("_pkt_ts", None)
    return env
