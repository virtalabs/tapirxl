"""Pydantic models for the vendor-neutral signal manifest schema (v1).

A *signal manifest* is a TOML file that fully describes the set of network
signatures a fixture generator should reproduce as a PCAP. Users author
manifests; the generator reads them. Multiple manifests (different vendors,
different scenarios) can coexist — the manifest format and these models are
vendor-neutral.

Load a manifest via :func:`tapirxl.fixtures.loader.load_signal_manifest`;
this module contains only types (no I/O).
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUPPORTED_SCHEMA_VERSION = 1

# ── Meta ──────────────────────────────────────────────────────────────────────


class Meta(BaseModel):
    schema_version: int
    manifest_id: str
    created_at: datetime

    @field_validator("schema_version")
    @classmethod
    def _check_version(cls, v: int) -> int:
        if v > SUPPORTED_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version {v} is newer than the loader supports "
                f"(max {SUPPORTED_SCHEMA_VERSION})"
            )
        if v < SUPPORTED_SCHEMA_VERSION:
            warnings.warn(
                f"schema_version {v} is deprecated; loader supports {SUPPORTED_SCHEMA_VERSION}",
                DeprecationWarning,
                stacklevel=2,
            )
        return v


# ── Scenario ──────────────────────────────────────────────────────────────────


class DhcpLease(BaseModel):
    lease_seconds: int = 86400
    t1_seconds: int = 43200
    t2_seconds: int = 75600


class ScenarioNetwork(BaseModel):
    dhcp_server_slug: str
    gateway_slug: str
    dns_server_ip: str
    subnet_mask: str = "255.255.255.0"

    @field_validator("dns_server_ip")
    @classmethod
    def _dns_server_ip_format(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError(f"dns_server_ip {v!r} is not a valid IP address") from exc


class ScenarioContext(BaseModel):
    domain: str
    pcap_base_timestamp: datetime
    intra_flow_step_s: float = 0.00001
    network: ScenarioNetwork
    dhcp_lease: DhcpLease = Field(default_factory=DhcpLease)


# ── Profiles ──────────────────────────────────────────────────────────────────


class Profile(BaseModel):
    """Reusable protocol-level signature block (REQ-MAN-003).

    Extra keys are allowed so forward-compatible additions do not require
    loader changes (REQ-EXT-001 spirit for profiles).
    """

    model_config = ConfigDict(extra="allow")
    description: str


# ── Per-asset solo protocol sub-models ────────────────────────────────────────


class AssetDhcp(BaseModel):
    """DHCP client configuration for a single asset.

    Unknown extra keys are accepted (REQ-EXT-001).
    """

    model_config = ConfigDict(extra="allow")

    dhcp_profile: str | None = None
    xid_discover: int | None = None
    xid_request: int | None = None
    option60_vci: str | None = None
    # PRL resolved from profile; override here if needed (REQ-REF-004)
    option55_prl: list[int] | None = None
    ip_ttl: int = 64
    emit_at_s: float = 0.0

    @field_validator("xid_discover", "xid_request")
    @classmethod
    def _xid_uint32(cls, v: int | None) -> int | None:
        if v is not None and v > 0xFFFF_FFFF:
            raise ValueError(f"xid value {v:#x} exceeds uint32 (REQ-VAL-005)")
        return v


class AssetWsDiscovery(BaseModel):
    """WS-Discovery Hello configuration for a single asset."""

    model_config = ConfigDict(extra="allow")

    uuid: str
    types: list[str]
    emit_at_s: float = 0.0


class AssetTcpSyn(BaseModel):
    """Single outbound TCP SYN fingerprint for a single asset.

    The *target* is resolved by a companion ``tcp_syn`` flow; this sub-model
    only carries the per-asset fingerprint profile reference.
    """

    model_config = ConfigDict(extra="allow")

    tcp_profile: str | None = None
    ip_ttl: int = 128
    mss: int = 1460
    window: int = 8192
    wscale: int = 8
    sack_permitted: bool = True


class AssetLlmnrResponse(BaseModel):
    """LLMNR self-announcement: the asset broadcasts its own hostname → IP."""

    model_config = ConfigDict(extra="allow")

    emit_at_s: float = 0.0


# ── Asset ─────────────────────────────────────────────────────────────────────

_KNOWN_SOLO_PROTOCOLS = frozenset({"dhcp", "wsdiscovery", "tcp_syn", "llmnr_response"})
_KNOWN_PROTOCOL_SUBTABLES = frozenset({"dhcp", "wsdiscovery", "tcp_syn", "llmnr_response"})
_ASSET_ROOT_ALLOWLIST = frozenset(
    {
        "hostname",
        "category",
        "mac_oui",
        "mac",
        "ip",
        "notes",
        "cve",
        "cpe",
        "emits",
    }
    | _KNOWN_PROTOCOL_SUBTABLES
)

_MAC_OUI_RE = re.compile(r"^([0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class Asset(BaseModel):
    """Description of a single network host including its signal fingerprint.

    Unknown keys at the asset root level are rejected (REQ-EXT-002).
    Protocol sub-table keys accept unknown extra keys (REQ-EXT-001).
    """

    model_config = ConfigDict(extra="forbid")

    hostname: str | None
    category: str
    mac_oui: str
    mac: str
    ip: str
    notes: str | None = None
    cve: str | None = None
    cpe: str | None = None
    emits: list[Literal["dhcp", "wsdiscovery", "tcp_syn", "llmnr_response"]] = Field(
        default_factory=list
    )
    dhcp: AssetDhcp | None = None
    wsdiscovery: AssetWsDiscovery | None = None
    tcp_syn: AssetTcpSyn | None = None
    llmnr_response: AssetLlmnrResponse | None = None

    @field_validator("hostname", mode="before")
    @classmethod
    def _empty_to_none(cls, v: object) -> object:
        return None if v == "" else v

    @field_validator("mac_oui")
    @classmethod
    def _mac_oui_format(cls, v: str) -> str:
        if not _MAC_OUI_RE.match(v):
            raise ValueError(
                f"mac_oui {v!r} must match XX:XX:XX (colon-separated hex octets, REQ-VAL-007)"
            )
        return v.lower()

    @field_validator("mac")
    @classmethod
    def _mac_format(cls, v: str) -> str:
        if not _MAC_RE.match(v):
            raise ValueError(f"mac {v!r} must match XX:XX:XX:XX:XX:XX (colon-separated hex octets)")
        return v.lower()

    @field_validator("ip")
    @classmethod
    def _ip_format(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError(f"ip {v!r} is not a valid IP address") from exc

    @model_validator(mode="after")
    def _mac_matches_oui(self) -> Asset:
        prefix = f"{self.mac_oui}:"
        if not self.mac.startswith(prefix):
            raise ValueError(f"mac {self.mac!r} must start with mac_oui prefix {self.mac_oui!r}")
        return self

    @model_validator(mode="after")
    def _emits_have_subtables(self) -> Asset:
        for proto in self.emits:
            if getattr(self, proto, None) is None:
                raise ValueError(f"asset declares emits=['{proto}'] but has no [{proto}] sub-table")
        return self


# ── Flow sub-models ───────────────────────────────────────────────────────────
# Each flow type uses a flat field layout (no TOML sub-tables inside [[flows]]
# array elements, which would be invalid TOML). Dataset fields are prefixed.


class FlowArpExchange(BaseModel):
    """ARP request from *requester* answered by *responder*."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["arp_exchange"]
    requester: str
    responder: str
    emit_at_s: float


class FlowDicomAssocAndCStore(BaseModel):
    """Full DICOM A-ASSOCIATE-RQ/AC + C-STORE-RQ/RSP exchange."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["dicom_associate_and_cstore"]
    client: str
    server: str
    emit_at_s: float
    client_port: int
    server_port: int = 104

    # DICOM association parameters
    called_ae: str
    calling_ae: str
    client_impl_class_uid: str
    client_impl_version: str
    server_impl_class_uid: str
    server_impl_version: str
    abstract_syntax: str
    transfer_syntax: str
    max_pdu: int = 16382
    message_id: int = 1
    sop_instance_uid: str

    # C-STORE dataset fields (prefixed dataset_*)
    dataset_patient_name: str
    dataset_modality: str
    dataset_manufacturer: str
    dataset_model: str
    dataset_software_versions: list[str]


class FlowSmb2Negotiate(BaseModel):
    """SMB2 Negotiate request (single TCP connection).

    ``client_guid_hex`` is decoded to ``bytes`` by the loader (REQ-BYT-002).
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["smb2_negotiate"]
    client: str
    server: str
    emit_at_s: float
    client_port: int
    client_guid_hex: bytes = bytes.fromhex("a1b2c3d4e5f6708190a0b0c0d0e0f101")
    dialects: list[int] = Field(default_factory=lambda: [0x0202, 0x0210])


class FlowSmb2NtlmsspSetup(BaseModel):
    """SMB2 SESSION_SETUP with NTLMSSP three-leg exchange.

    ``server_challenge_hex`` and ``version_hex`` are decoded to ``bytes`` by
    the loader (REQ-BYT-002).
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["smb2_session_setup_ntlmssp"]
    client: str
    server: str
    emit_at_s: float
    client_port: int
    domain: str
    username: str
    server_challenge_hex: bytes
    version_hex: bytes


class FlowTlsClientHello(BaseModel):
    """TLS ClientHello toward an external IP (L2 via relay asset MAC)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["tls_client_hello"]
    client: str
    server_ip: str
    server_mac_via: str  # slug of asset whose MAC is used as L2 dst
    emit_at_s: float
    client_port: int
    sni: str

    @field_validator("server_ip")
    @classmethod
    def _server_ip_format(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise ValueError(f"server_ip {v!r} is not a valid IP address") from exc


class FlowLlmnrQuery(BaseModel):
    """Single LLMNR multicast query from *client* for *qname*."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["llmnr_query"]
    client: str
    qname: str
    emit_at_s: float


class FlowTcpSyn(BaseModel):
    """Single outbound TCP SYN (fingerprint probe) from *client* to *server*."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["tcp_syn"]
    client: str
    server: str
    emit_at_s: float
    client_port: int
    server_port: int
    tcp_profile: str | None = None
    # Profile fields may be resolved from profiles table by loader
    ip_ttl: int = 128
    mss: int = 1460
    window: int = 8192
    wscale: int = 8
    sack_permitted: bool = True


# ── Discriminated union ───────────────────────────────────────────────────────

Flow = Annotated[
    FlowArpExchange
    | FlowDicomAssocAndCStore
    | FlowSmb2Negotiate
    | FlowSmb2NtlmsspSetup
    | FlowTlsClientHello
    | FlowLlmnrQuery
    | FlowTcpSyn,
    Field(discriminator="type"),
]


# ── Top-level SignalManifest ───────────────────────────────────────────────────


class SignalManifest(BaseModel):
    """Root manifest type.  Load via :func:`tapirxl.fixtures.loader.load_signal_manifest`."""

    meta: Meta
    scenario: ScenarioContext
    profiles: dict[str, Profile]
    assets: dict[str, Asset]
    flows: list[Flow] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_unique_hostnames(self) -> SignalManifest:
        # REQ-VAL-006: duplicate hostnames
        seen: dict[str, str] = {}
        for slug, asset in self.assets.items():
            if asset.hostname:
                if asset.hostname in seen:
                    raise ValueError(
                        f"duplicate hostname {asset.hostname!r}: assets "
                        f"{seen[asset.hostname]!r} and {slug!r} (REQ-VAL-006)"
                    )
                seen[asset.hostname] = slug
        return self

    @model_validator(mode="after")
    def _check_flow_slug_references(self) -> SignalManifest:
        # Flow slug references must resolve
        for i, flow in enumerate(self.flows):
            for attr in ("client", "server", "requester", "responder", "asset"):
                if not hasattr(flow, attr):
                    continue
                slug = getattr(flow, attr)
                if slug not in self.assets:
                    raise ValueError(
                        f"flows[{i}] ({flow.type}) references unknown asset slug {slug!r}"
                    )
            if hasattr(flow, "server_mac_via"):
                slug = flow.server_mac_via  # type: ignore[union-attr]
                if slug not in self.assets:
                    raise ValueError(
                        f"flows[{i}] ({flow.type}) server_mac_via references unknown slug {slug!r}"
                    )
        return self

    @model_validator(mode="after")
    def _check_asset_profile_references(self) -> SignalManifest:
        for slug, asset in self.assets.items():
            if asset.dhcp and asset.dhcp.dhcp_profile:
                if asset.dhcp.dhcp_profile not in self.profiles:
                    raise ValueError(
                        f"asset {slug!r} dhcp_profile {asset.dhcp.dhcp_profile!r} "
                        f"not found in [profiles] (REQ-REF-003)"
                    )
            if asset.tcp_syn and asset.tcp_syn.tcp_profile:
                if asset.tcp_syn.tcp_profile not in self.profiles:
                    raise ValueError(
                        f"asset {slug!r} tcp_profile {asset.tcp_syn.tcp_profile!r} "
                        f"not found in [profiles] (REQ-REF-003)"
                    )
        return self

    @model_validator(mode="after")
    def _check_flow_profile_references(self) -> SignalManifest:
        for i, flow in enumerate(self.flows):
            if isinstance(flow, FlowTcpSyn) and flow.tcp_profile:
                if flow.tcp_profile not in self.profiles:
                    raise ValueError(
                        f"flows[{i}] tcp_profile {flow.tcp_profile!r} not found in [profiles]"
                    )
        return self

    @model_validator(mode="after")
    def _check_scenario_slug_references(self) -> SignalManifest:
        # Scenario network slugs must resolve
        net = self.scenario.network
        if net.dhcp_server_slug not in self.assets:
            raise ValueError(
                f"scenario.network.dhcp_server_slug {net.dhcp_server_slug!r} "
                "must reference an asset"
            )
        if net.gateway_slug not in self.assets:
            raise ValueError(
                f"scenario.network.gateway_slug {net.gateway_slug!r} must reference an asset"
            )
        return self
