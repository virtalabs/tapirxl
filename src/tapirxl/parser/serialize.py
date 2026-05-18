"""Flat runtime envelope to typed `HostEnvelope` projection.

The parser pipeline produces a flat `dict` (see `envelope_builder.py`) for
historical reasons. This module is the single seam that promotes that flat
dict to the typed `HostEnvelope` declared in `schemas/envelope.py`, which is
the wire contract for downstream bounded contexts.

Pipeline blocks are returned as `None` (absent) when the pipeline did not
fire — never empty objects. Internal helper keys (`_pkt_ts`, `_seen_ts`,
`_ssh_banners`, `_processing_path`, `_deterministic_preset`) are dropped;
top-level duplicates of triage fields (`signal_count`, `floor_triggers`,
`expert_flags`, `contradictions`) survive only under the `triage` block.
"""

from __future__ import annotations

from typing import Any

from tapirxl.schemas.envelope import (
    CapsuleMdipBlock,
    DeterministicConsensus,
    DhcpBlock,
    DicomAssociationBlock,
    DicomTagsBlock,
    DnsBlock,
    EthernetBlock,
    Hl7Block,
    HostEnvelope,
    KerberosBlock,
    LlmnrBlock,
    LmEnvelopeBlock,
    MdnsBlock,
    MdnsSpoofCheck,
    NtlmsspBlock,
    Pipeline1Block,
    Pipeline2Block,
    Pipeline3Block,
    Smb2Block,
    SnmpBlock,
    SsdpBlock,
    SshBlock,
    TcpSynBlock,
    TlsSniBlock,
    TriageBlock,
    WsDiscoveryBlock,
)


def _is_locally_administered(mac: str) -> bool:
    """Return True when the U/L bit of the first octet's second hex digit is set."""
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError, IndexError:
        return False
    return bool(first_octet & 0b0000_0010)


def _to_ethernet(env: dict) -> EthernetBlock | None:
    mac = env.get("mac") or ""
    if not mac:
        return None
    return EthernetBlock(
        mac=mac,
        oui_vendor=env.get("oui_vendor") or "UNKNOWN",
        is_locally_administered=_is_locally_administered(mac),
        ttl_observations=[],
    )


def _to_pipeline_1(env: dict) -> Pipeline1Block | None:
    if not env.get("pipeline_1"):
        return None
    p1 = env["pipeline_1"]
    block = Pipeline1Block()

    if env.get("ws_uuid"):
        block.ws_discovery = WsDiscoveryBlock(
            uuid=env.get("ws_uuid"),
            vendor_prefix_hex=env.get("ws_vendor_prefix"),
            series_code_hex=env.get("ws_series_code"),
            types=list(env.get("ws_types") or []),
            scopes=list(env.get("ws_scopes") or []),
            deterministic_label=p1.get("deterministic_label"),
            deterministic_confidence=p1.get("deterministic_confidence"),
        )

    has_mdns = bool(
        env.get("mdns_hostname")
        or env.get("mdns_txt_raw")
        or env.get("mdns_txt_parsed")
        or env.get("dns_sd_services")
    )
    if has_mdns:
        contradiction_codes = (env.get("triage") or {}).get("contradiction_codes") or []
        spoof = MdnsSpoofCheck(spoof_suspected="C2" in contradiction_codes)
        block.mdns = MdnsBlock(
            hostname=env.get("mdns_hostname"),
            txt_parsed=dict(env.get("mdns_txt_parsed") or {}),
            txt_raw=list(env.get("mdns_txt_raw") or []),
            dns_sd_services=list(env.get("dns_sd_services") or []),
            ptr_records=list(env.get("dns_sd_services") or []),
            spoof_check=spoof,
        )

    ssdp_obs = env.get("ssdp_observations") or []
    if ssdp_obs:
        first = ssdp_obs[0]
        block.ssdp = SsdpBlock(
            server_header=first.get("server") or None,
            usn=first.get("usn") or None,
        )

    if env.get("llmnr_queries") or env.get("llmnr_hostname"):
        block.llmnr = LlmnrBlock(
            queries_emitted=list(env.get("llmnr_queries") or []),
            claimed_hostname=env.get("llmnr_hostname"),
        )

    capsule = env.get("capsule_mdip") or {}
    if capsule:
        tokens = capsule.get("tokens") or []
        block.capsule_mdip = CapsuleMdipBlock(
            udp_5090_present=bool(capsule.get("udp5090")),
            apdu_client_token=tokens[0] if tokens else None,
            tls_tcp_5090=bool(capsule.get("tls")),
        )

    if not any([block.ws_discovery, block.mdns, block.ssdp, block.llmnr, block.capsule_mdip]):
        return None
    return block


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except TypeError, ValueError:
        return None


def _to_pipeline_2(env: dict) -> Pipeline2Block | None:
    p2 = env.get("pipeline_2")
    if not p2:
        return None
    block = Pipeline2Block()

    syn_list = p2.get("syn_fingerprints") or []
    if syn_list:
        first = syn_list[0]
        feats = first.get("syn_features") or {}
        block.tcp_syn_fingerprint = TcpSynBlock(
            ttl=_coerce_int(feats.get("ttl")),
            mss=_coerce_int(feats.get("mss")),
            window_scale=_coerce_int(feats.get("window_scale")),
            sack_perm=feats.get("sack_permitted")
            if isinstance(feats.get("sack_permitted"), bool)
            else None,
            timestamp_option=feats.get("timestamp_option")
            if isinstance(feats.get("timestamp_option"), bool)
            else None,
            deterministic_label=first.get("deterministic_syn_label"),
            deterministic_confidence=first.get("confidence_hint"),
        )

    sni_hits = p2.get("sni_hits") or []
    if sni_hits:
        sni_domains: list[str] = []
        ecosystem_hints: list[str] = []
        for hit in sni_hits:
            sni = hit.get("sni") or ""
            for part in str(sni).split("|"):
                part = part.strip()
                if part and part not in sni_domains:
                    sni_domains.append(part)
            for hint in hit.get("ecosystem_hints") or []:
                if hint not in ecosystem_hints:
                    ecosystem_hints.append(hint)
        block.tls_sni = TlsSniBlock(
            sni_domains=sni_domains,
            ecosystem_hints=ecosystem_hints,
        )

    smb2_list = p2.get("smb2_negotiate") or []
    ntlmssp_list = p2.get("ntlmssp") or []
    if smb2_list or ntlmssp_list:
        first_smb = smb2_list[0] if smb2_list else {}
        ntlmssp_block: NtlmsspBlock | None = None
        if ntlmssp_list:
            first_ntlm = ntlmssp_list[0]
            ntlmssp_block = NtlmsspBlock(
                target_computer=(first_ntlm.get("ntlmssp_target_nb_computer_name") or None)
                or (first_ntlm.get("ntlmssp_target_name") or None),
                workstation=first_ntlm.get("ntlmssp_auth_workstation") or None,
                domain=first_ntlm.get("ntlmssp_auth_domain") or None,
            )
        dialects_sample = first_smb.get("dialects_sample") or ""
        dialects_offered = [d.strip() for d in dialects_sample.split(",") if d.strip()]
        block.smb2 = Smb2Block(
            dialects_offered=dialects_offered,
            dialect_negotiated=first_smb.get("dialect_revision") or None,
            signing_required=None,
            ntlmssp=ntlmssp_block,
        )

    kerberos_list = p2.get("kerberos") or []
    if kerberos_list:
        first = kerberos_list[0]
        block.kerberos = KerberosBlock(
            realm=first.get("realm") or None,
            cname_observed=first.get("client_name_hint") or None,
        )

    dns_lookups = p2.get("dns_lookups") or []
    if dns_lookups:
        queries: list[str] = []
        responses: list[str] = []
        vendor_hits: list[str] = []
        for entry in dns_lookups:
            qname = entry.get("qname")
            if qname and qname not in queries:
                queries.append(qname)
            for hit in entry.get("vendor_domain_hits") or []:
                if hit not in vendor_hits:
                    vendor_hits.append(hit)
        block.dns = DnsBlock(
            queries=queries,
            responses=responses,
            vendor_domain_hits=vendor_hits,
        )

    ssh_banners = env.get("_ssh_banners") or []
    if ssh_banners:
        block.ssh = SshBlock(banner=ssh_banners[0])

    if not any(
        [
            block.tcp_syn_fingerprint,
            block.tls_sni,
            block.smb2,
            block.kerberos,
            block.dns,
            block.ssh,
        ]
    ):
        return None
    return block


def _to_dicom_block(raw: dict) -> DicomAssociationBlock:
    assoc = raw.get("dicom_association") or {}
    sw_versions_raw = assoc.get("dicom_software_versions")
    if isinstance(sw_versions_raw, list):
        sw_versions = [str(v) for v in sw_versions_raw if v]
    elif sw_versions_raw:
        sw_versions = [str(sw_versions_raw)]
    else:
        sw_versions = []
    tags = DicomTagsBlock(
        manufacturer=assoc.get("dicom_manufacturer") or None,
        model_name=assoc.get("dicom_manufacturer_model") or None,
        software_versions=sw_versions,
        modality=assoc.get("dicom_modality") or None,
    )
    image_uid_arc_hits = assoc.get("philips_image_uid_arc_hits") or []
    image_uid_arc_counts: dict[str, int] = {}
    for arc in image_uid_arc_hits:
        image_uid_arc_counts[arc] = image_uid_arc_counts.get(arc, 0) + 1

    return DicomAssociationBlock(
        implementation_class_uid=assoc.get("implementation_class_uid") or None,
        implementation_version_name=assoc.get("implementation_version_name") or None,
        sop_classes_negotiated=list(assoc.get("sop_class_hints") or []),
        image_uid_arc_counts=image_uid_arc_counts,
        pdu_type_byte=assoc.get("pdu_type_byte") or None,
        tags=tags,
    )


def _to_dhcp_block(raw: dict) -> DhcpBlock:
    return DhcpBlock(
        option60_vendor_class=raw.get("option60_vendor_class") or None,
        option12_hostname=raw.get("option12_hostname_hint") or None,
        param_request_list=raw.get("option55_key_guess") or None,
        fingerbank_dhcp_hit=raw.get("fingerbank_dhcp_hit") or None,
    )


def _to_hl7_block(raw: dict) -> Hl7Block:
    return Hl7Block(
        mllp_detected=True,
        sending_app=raw.get("sending_app_raw") or None,
        deterministic_label=raw.get("sending_facility_normalized_hint") or None,
    )


def _to_snmp_block(raw: dict) -> SnmpBlock:
    return SnmpBlock(
        sys_descr=raw.get("sys_descr") or None,
        sys_name=raw.get("sys_name") or None,
        sys_object_id=raw.get("sys_object_id") or None,
        deterministic_label=raw.get("deterministic_descr_label") or None,
    )


def _to_pipeline_3(env: dict) -> Pipeline3Block | None:
    p3 = env.get("pipeline_3")
    if not p3:
        return None

    dicom_assoc = [_to_dicom_block(r) for r in (p3.get("dicom_association") or [])]
    dhcp = [_to_dhcp_block(r) for r in (p3.get("dhcp") or [])]
    hl7 = [_to_hl7_block(r) for r in (p3.get("hl7_segments") or [])]
    snmp = [_to_snmp_block(r) for r in (p3.get("snmp_sysdescr") or [])]

    if not (dicom_assoc or dhcp or hl7 or snmp):
        return None

    return Pipeline3Block(
        dicom_association=dicom_assoc,
        dhcp=dhcp,
        hl7=hl7,
        snmp=snmp,
    )


def _to_triage(env: dict) -> TriageBlock:
    triage = env.get("triage") or {}
    consensus_raw = triage.get("deterministic_consensus")
    if consensus_raw:
        consensus = DeterministicConsensus(
            device_class=consensus_raw.get("label"),
            confidence=consensus_raw.get("confidence"),
        )
    else:
        consensus = DeterministicConsensus()

    return TriageBlock(
        signal_count=int(env.get("signal_count") or 0),
        pipelines_fired=list(triage.get("pipelines_fired") or []),
        floor_triggers=list(env.get("floor_triggers") or []),
        expert_flags=list(env.get("expert_flags") or []),
        deterministic_consensus=consensus,
        deterministic_contradictions=list(env.get("contradictions") or []),
        contradiction_codes=list(triage.get("contradiction_codes") or []),
        routing=triage.get("routing"),
    )


def _to_lm_envelope(env: dict) -> LmEnvelopeBlock:
    lm = env.get("lm_envelope") or {}
    return LmEnvelopeBlock(
        ambiguous_fields=list(lm.get("ambiguous_fields") or []),
    )


def to_envelope(env: dict) -> HostEnvelope:
    """Project the flat runtime envelope into the typed `HostEnvelope`.

    Drops internal scaffolding keys and top-level duplicates of triage
    fields. Pipeline blocks return `None` when no member protocol fired.
    """
    return HostEnvelope(
        host_id=env["host_id"],
        oui_vendor=env.get("oui_vendor") or "UNKNOWN",
        ip_observations=list(env.get("ip_observations") or []),
        first_seen=env.get("first_seen_ts"),
        last_seen=env.get("last_seen_ts"),
        ethernet=_to_ethernet(env),
        pipeline_1=_to_pipeline_1(env),
        pipeline_2=_to_pipeline_2(env),
        pipeline_3=_to_pipeline_3(env),
        triage=_to_triage(env),
        lm_envelope=_to_lm_envelope(env),
    )
