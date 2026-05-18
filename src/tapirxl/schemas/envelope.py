"""Pydantic v2 models for the per-packet and per-MAC envelope schemas.

These are the v3.0 target contracts (ARCHITECTURE.md §3). The monolith uses
raw dicts until M3/M4; these models are the migration destination.

Primary key is host_id (MAC). IP is observational. Pipeline blocks are absent
(None), not empty dicts, when the pipeline did not fire.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class SignalObservation(BaseModel):
    """Internal per-packet record emitted by a protocol extractor."""

    model_config = ConfigDict(extra="allow")

    pipeline: Literal[1, 2, 3]
    protocol: str
    src_mac: str
    src_ip: str | None = None
    dst_ip: str | None = None
    timestamp: float
    fields: dict[str, Any] = Field(default_factory=dict)
    expert_flag: bool = False
    expert_message: str = ""


# ── Pipeline sub-block models (typed but permissive for forward compat) ────────


class DeterministicTriplet(BaseModel):
    """Shared deterministic_label/confidence/candidate_labels triplet."""

    model_config = ConfigDict(extra="allow")

    deterministic_label: str | None = None
    deterministic_confidence: str | None = None
    candidate_labels: list[str] = Field(default_factory=list)


class WsDiscoveryBlock(DeterministicTriplet):
    uuid: str | None = None
    vendor_prefix_hex: str | None = None
    vendor_prefix_ascii: str | None = None
    series_code_hex: str | None = None
    series_code_ascii: str | None = None
    types: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    app_sequence_instance_id: str | None = None


class MdnsSpoofCheck(BaseModel):
    mac_locally_administered: bool = False
    oui_matches_advertised_mfg: bool = True
    spoof_suspected: bool = False


class MdnsBlock(DeterministicTriplet):
    hostname: str | None = None
    txt_parsed: dict[str, Any] = Field(default_factory=dict)
    txt_raw: list[str] = Field(default_factory=list)
    dns_sd_services: list[str] = Field(default_factory=list)
    ptr_records: list[str] = Field(default_factory=list)
    spoof_check: MdnsSpoofCheck = Field(default_factory=MdnsSpoofCheck)


class SsdpBlock(DeterministicTriplet):
    server_header: str | None = None
    usn: str | None = None
    nt: str | None = None
    location_url: str | None = None
    nts: str | None = None


class LlmnrBlock(BaseModel):
    queries_emitted: list[str] = Field(default_factory=list)
    claimed_hostname: str | None = None
    hostname_pattern_match: str | None = None


class CapsuleMdipBlock(DeterministicTriplet):
    udp_5090_present: bool = False
    apdu_client_token: str | None = None
    session_rate_hz: float | None = None
    peer_ip: str | None = None
    tls_tcp_5090: bool = False


class Pipeline1Block(BaseModel):
    model_config = ConfigDict(extra="allow")

    ws_discovery: WsDiscoveryBlock | None = None
    mdns: MdnsBlock | None = None
    ssdp: SsdpBlock | None = None
    llmnr: LlmnrBlock | None = None
    capsule_mdip: CapsuleMdipBlock | None = None


class TcpSynBlock(DeterministicTriplet):
    ttl: int | None = None
    mss: int | None = None
    window_scale: int | None = None
    sack_perm: bool | None = None
    timestamp_option: bool | None = None


class TlsSniBlock(DeterministicTriplet):
    sni_domains: list[str] = Field(default_factory=list)
    ja3_client: str | None = None
    ja3s_server: str | None = None
    ecosystem_hints: list[str] = Field(default_factory=list)


class NtlmsspBlock(BaseModel):
    target_computer: str | None = None
    workstation: str | None = None
    domain: str | None = None


class Smb2Block(BaseModel):
    dialects_offered: list[str] = Field(default_factory=list)
    dialect_negotiated: str | None = None
    signing_required: bool | None = None
    ntlmssp: NtlmsspBlock | None = None


class KerberosBlock(BaseModel):
    realm: str | None = None
    cname_observed: str | None = None


class DnsBlock(BaseModel):
    queries: list[str] = Field(default_factory=list)
    responses: list[str] = Field(default_factory=list)
    vendor_domain_hits: list[str] = Field(default_factory=list)


class SshBlock(BaseModel):
    banner: str | None = None
    kex_algorithms: list[str] = Field(default_factory=list)


class Pipeline2Block(BaseModel):
    model_config = ConfigDict(extra="allow")

    tcp_syn_fingerprint: TcpSynBlock | None = None
    tls_sni: TlsSniBlock | None = None
    smb2: Smb2Block | None = None
    kerberos: KerberosBlock | None = None
    dns: DnsBlock | None = None
    ssh: SshBlock | None = None


class DicomTagsBlock(BaseModel):
    model_config = ConfigDict(extra="allow")

    manufacturer: str | None = None  # (0008,0070)
    model_name: str | None = None  # (0008,1090)
    software_versions: list[str] = Field(default_factory=list)  # (0018,1020)
    device_serial_number: str | None = None  # (0018,1000)
    modality: str | None = None  # (0008,0060)
    institution_name: str | None = None  # (0008,0080) — not PHI, retained


class DicomAssociationBlock(DeterministicTriplet):
    implementation_class_uid: str | None = None
    impl_class_uid_vendor_arc: str | None = None
    implementation_version_name: str | None = None
    ae_titles_calling: list[str] = Field(default_factory=list)
    ae_titles_called: list[str] = Field(default_factory=list)
    sop_classes_negotiated: list[str] = Field(default_factory=list)
    transfer_syntaxes: list[str] = Field(default_factory=list)
    image_uid_arc_counts: dict[str, int] = Field(default_factory=dict)
    pdu_type_byte: str | None = None
    tags: DicomTagsBlock = Field(default_factory=DicomTagsBlock)


class DhcpBlock(DeterministicTriplet):
    events: list[str] = Field(default_factory=list)
    option60_vendor_class: str | None = None
    option12_hostname: str | None = None
    param_request_list: str | None = None
    fingerbank_dhcp_hit: str | None = None
    lease_yiaddr: str | None = None


class Hl7Block(DeterministicTriplet):
    mllp_detected: bool = False
    sending_app: str | None = None
    receiving_app: str | None = None
    message_types: list[str] = Field(default_factory=list)
    version: str | None = None
    interface_endpoint: str | None = None


class SnmpBlock(DeterministicTriplet):
    version: str | None = None
    community: str | None = None
    sys_descr: str | None = None
    sys_name: str | None = None
    sys_object_id: str | None = None


class Pipeline3Block(BaseModel):
    model_config = ConfigDict(extra="allow")

    dicom_association: list[DicomAssociationBlock] = Field(default_factory=list)
    dhcp: list[DhcpBlock] = Field(default_factory=list)
    hl7: list[Hl7Block] = Field(default_factory=list)
    snmp: list[SnmpBlock] = Field(default_factory=list)


# ── Triage block ───────────────────────────────────────────────────────────────


class DeterministicConsensus(BaseModel):
    device_class: str | None = None
    confidence: str | None = None
    supporting_pipelines: list[int] = Field(default_factory=list)
    supporting_signals: list[str] = Field(default_factory=list)


TriageRouting = Literal["SKIP", "STAMP_LOW", "DETERMINISTIC_FINAL", "AMBIGUOUS"]


class TriageBlock(BaseModel):
    model_config = ConfigDict(extra="allow")

    signal_count: int = 0
    pipelines_fired: list[int] = Field(default_factory=list)
    floor_triggers: list[str] = Field(default_factory=list)
    expert_flags: list[str] = Field(default_factory=list)
    deterministic_consensus: DeterministicConsensus = Field(default_factory=DeterministicConsensus)
    deterministic_contradictions: list[str] = Field(default_factory=list)
    contradiction_codes: list[str] = Field(default_factory=list)
    routing: TriageRouting | None = None


# ── LM envelope block ──────────────────────────────────────────────────────────


class AmbiguousFieldEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    raw_value: str
    source_protocol: str
    source_pipeline: int
    field_path: str
    candidate_labels: list[str] = Field(default_factory=list)
    host_context: dict[str, Any] = Field(default_factory=dict)


class LmEnvelopeBlock(BaseModel):
    ambiguous_fields: list[AmbiguousFieldEntry] = Field(default_factory=list)


# ── EthernetBlock ──────────────────────────────────────────────────────────────


class EthernetBlock(BaseModel):
    mac: str
    oui_vendor: str = "UNKNOWN"
    is_locally_administered: bool = False
    ttl_observations: list[int] = Field(default_factory=list)


# ── Top-level HostEnvelope ─────────────────────────────────────────────────────


class HostEnvelope(BaseModel):
    """Canonical per-MAC record. Primary key is host_id (MAC). IP is observational.
    Pipeline blocks are None (absent) when the pipeline did not fire — never empty dicts.

    Top-level fields are closed (`extra="forbid"`); sub-block models retain
    `extra="allow"` so extractor-side field drift is tolerated until the
    sub-block shapes are tightened in a later phase.
    """

    model_config = ConfigDict(extra="forbid")

    host_id: str  # lowercase colon-delimited MAC
    oui_vendor: str = "UNKNOWN"
    ip_observations: list[str] = Field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None
    ethernet: EthernetBlock | None = None
    pipeline_1: Pipeline1Block | None = None
    pipeline_2: Pipeline2Block | None = None
    pipeline_3: Pipeline3Block | None = None
    triage: TriageBlock | None = None
    lm_envelope: LmEnvelopeBlock | None = None
