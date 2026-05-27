"""Unit tests for the signal manifest loader and Pydantic models.

Coverage targets (per plan):
    REQ-VAL-001 thru 007  schema validation
    REQ-REF-001 thru 004  profile merge and cross-reference checks
    REQ-BYT-002      _hex key decoding to bytes
    REQ-LOD-004      empty assets/flows manifests are valid
    Cross-ref        flow/slug resolution, dhcp_server_slug, gateway_slug
    Emits-consistency asset emits a protocol but has no sub-table
"""

from __future__ import annotations

from textwrap import dedent

import pytest

from tapirxl.fixtures.loader import ManifestValidationError, load_signal_manifest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_toml(tmp_path, content: str):
    """Write a TOML string to a temp file and load it."""
    p = tmp_path / "test_manifest.toml"
    p.write_text(dedent(content))
    return load_signal_manifest(p)


_BASE = """\
[meta]
schema_version = 1
manifest_id    = "test"
created_at     = 2026-01-01T00:00:00Z

[scenario]
domain              = "TESTNET"
pcap_base_timestamp = "2026-01-01T00:00:00Z"

[scenario.network]
dhcp_server_slug = "srv"
gateway_slug     = "gw"
dns_server_ip    = "10.0.0.1"

[profiles]

[assets.srv]
hostname = "SRV01"
category = "infrastructure"
mac_oui  = "00:11:22"
mac      = "00:11:22:33:44:55"
ip       = "10.0.0.1"
emits    = []

[assets.gw]
hostname = "GW01"
category = "firewall"
mac_oui  = "00:aa:bb"
mac      = "00:aa:bb:cc:dd:ee"
ip       = "10.0.0.254"
emits    = []
"""


# ── Happy path ────────────────────────────────────────────────────────────────


def test_shipped_manifest_loads():
    """REQ-LOD-001: default (no path) loads the bundled signal_manifest.toml."""
    m = load_signal_manifest()
    assert len(m.assets) == 8
    assert len(m.profiles) == 4
    assert any(f.type == "dicom_associate_and_cstore" for f in m.flows)
    assert any(f.type == "smb2_session_setup_ntlmssp" for f in m.flows)
    assert any(f.type == "tls_client_hello" for f in m.flows)


def test_shipped_manifest_flow_types():
    m = load_signal_manifest()
    types = {f.type for f in m.flows}
    assert "arp_exchange" in types
    assert "dicom_associate_and_cstore" in types
    assert "smb2_negotiate" in types
    assert "smb2_session_setup_ntlmssp" in types
    assert "tls_client_hello" in types
    assert "llmnr_query" in types
    assert "tcp_syn" in types


def test_profile_merge_populates_prl(tmp_path):
    """REQ-REF-001: dhcp_profile reference merges option55_prl into the asset sub-table."""
    m = _load_toml(
        tmp_path,
        _BASE
        + """\

[profiles.myprofile]
description  = "test profile"
option55_prl = [1, 3, 6]

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]

[assets.client.dhcp]
dhcp_profile = "myprofile"
xid_discover = 0xAABBCCDD
xid_request  = 0xAABBCCD0
""",
    )
    assert m.assets["client"].dhcp is not None
    assert m.assets["client"].dhcp.option55_prl == [1, 3, 6]


def test_profile_merge_asset_overrides(tmp_path):
    """REQ-REF-004: asset explicit keys override profile values."""
    m = _load_toml(
        tmp_path,
        _BASE
        + """\

[profiles.base_profile]
description  = "base"
option55_prl = [1, 3, 6]
ip_ttl       = 64

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:02"
ip       = "10.0.0.11"
emits    = ["dhcp"]

[assets.client.dhcp]
dhcp_profile = "base_profile"
xid_discover = 0xAABBCCDD
xid_request  = 0xAABBCCD0
ip_ttl       = 128   # override
""",
    )
    assert m.assets["client"].dhcp.ip_ttl == 128


def test_hex_decode(tmp_path):
    """REQ-BYT-002: _hex-suffixed string values are decoded to bytes."""
    m = _load_toml(
        tmp_path,
        _BASE
        + """\

[[flows]]
type                 = "smb2_session_setup_ntlmssp"
client               = "srv"
server               = "gw"
emit_at_s            = 0.0
client_port          = 49300
domain               = "TESTNET"
username             = "user"
server_challenge_hex = "0123456789abcdef"
version_hex          = "0601b11d0000000f"
""",
    )
    flow = next(f for f in m.flows if f.type == "smb2_session_setup_ntlmssp")
    assert isinstance(flow.server_challenge_hex, bytes)
    assert flow.server_challenge_hex == bytes.fromhex("0123456789abcdef")
    assert isinstance(flow.version_hex, bytes)


# ── REQ-VAL validation errors ─────────────────────────────────────────────────


def test_missing_required_field_raises(tmp_path):
    """REQ-VAL-002: missing required asset fields (category) → ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.bad]
hostname = "BAD"
# missing category, mac_oui, mac, ip
mac_oui  = "00:11:22"
mac      = "00:11:22:aa:bb:cc"
ip       = "10.0.0.99"
emits    = []
""",
        )


def test_schema_version_too_new_raises(tmp_path):
    """REQ-VAL-003: schema_version > SUPPORTED raises ManifestValidationError."""
    content = _BASE.replace("schema_version = 1", "schema_version = 99")
    with pytest.raises(ManifestValidationError):
        _load_toml(tmp_path, content)


def test_schema_version_zero_warns(tmp_path):
    """REQ-VAL-004: schema_version < current emits DeprecationWarning but still loads."""
    content = _BASE.replace("schema_version = 1", "schema_version = 0")
    with pytest.warns(DeprecationWarning):
        m = _load_toml(tmp_path, content)
    assert m.meta.schema_version == 0


def test_xid_exceeds_uint32_raises(tmp_path):
    """REQ-VAL-005: xid_discover > 0xFFFFFFFF raises ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]

[assets.client.dhcp]
xid_discover = 0x1_0000_0000
xid_request  = 0xAABBCCD0
""",
        )


def test_duplicate_hostname_raises(tmp_path):
    """REQ-VAL-006: two assets with the same hostname raise ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.a1]
hostname = "DUPE"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = []

[assets.a2]
hostname = "DUPE"
category = "server"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:02"
ip       = "10.0.0.11"
emits    = []
""",
        )


def test_bad_mac_oui_raises(tmp_path):
    """REQ-VAL-007: mac_oui not matching XX:XX:XX raises ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.bad]
hostname = "BAD"
category = "workstation"
mac_oui  = "00:09"   # only 2 octets — invalid
mac      = "00:09:fb:bd:75:6d"
ip       = "10.0.0.10"
emits    = []
""",
        )


def test_bad_mac_raises(tmp_path):
    """Invalid full MAC (5 octets) raises ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.bad]
hostname = "BAD"
category = "workstation"
mac_oui  = "00:09:fb"
mac      = "00:09:fb:bd:75:6"   # only 5 octets — invalid
ip       = "10.0.0.10"
emits    = []
""",
        )


def test_bad_ip_raises(tmp_path):
    """Malformed IP address raises ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.bad]
hostname = "BAD"
category = "workstation"
mac_oui  = "00:09:fb"
mac      = "00:09:fb:bd:75:6d"
ip       = "10.10.10..21"
emits    = []
""",
        )


def test_bad_dns_server_ip_raises(tmp_path):
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE.replace('dns_server_ip    = "10.0.0.1"', 'dns_server_ip    = "10.10.20..7"'),
        )


def test_bad_tls_server_ip_raises(tmp_path):
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """

[[flows]]
type             = "tls_client_hello"
client           = "gw"
server_ip        = "not-an-ip"
server_mac_via   = "srv"
emit_at_s        = 30.0
client_port      = 49302
sni              = "example.com"
""",
        )


def test_mac_oui_prefix_mismatch_raises(tmp_path):
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.bad]
hostname = "BAD"
category = "workstation"
mac_oui  = "00:11:22"
mac      = "00:09:fb:bd:75:6d"
ip       = "10.0.0.10"
emits    = []
""",
        )


# ── REQ-REF reference checks ──────────────────────────────────────────────────


def test_missing_profile_reference_raises(tmp_path):
    """REQ-REF-003: dhcp_profile references a non-existent profile → error."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]

[assets.client.dhcp]
dhcp_profile = "nonexistent_profile"
xid_discover = 0xAABBCCDD
xid_request  = 0xAABBCCD0
""",
        )


def test_flow_tcp_profile_merge_populates_fingerprint(tmp_path):
    """REQ-REF-001: tcp_profile on a flow merges fingerprint fields from [profiles]."""
    m = _load_toml(
        tmp_path,
        _BASE
        + """\

[profiles.tcp_syn_linux]
description = "Linux TCP SYN fingerprint"
ip_ttl      = 64
wscale      = 7

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = []

[[flows]]
type        = "tcp_syn"
client      = "client"
server      = "srv"
emit_at_s   = 0.0
client_port = 49301
server_port = 445
tcp_profile = "tcp_syn_linux"
""",
    )
    flow = m.flows[0]
    assert flow.type == "tcp_syn"
    assert flow.ip_ttl == 64
    assert flow.wscale == 7


def test_flow_tcp_profile_override_wins(tmp_path):
    """REQ-REF-004: flow explicit keys override profile values."""
    m = _load_toml(
        tmp_path,
        _BASE
        + """\

[profiles.tcp_syn_linux]
description = "Linux TCP SYN fingerprint"
ip_ttl      = 64
wscale      = 7

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = []

[[flows]]
type        = "tcp_syn"
client      = "client"
server      = "srv"
emit_at_s   = 0.0
client_port = 49301
server_port = 445
tcp_profile = "tcp_syn_linux"
wscale      = 9
""",
    )
    flow = m.flows[0]
    assert flow.ip_ttl == 64
    assert flow.wscale == 9


def test_flow_missing_tcp_profile_raises(tmp_path):
    """REQ-REF-003: flow tcp_profile references a non-existent profile → error."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = []

[[flows]]
type        = "tcp_syn"
client      = "client"
server      = "srv"
emit_at_s   = 0.0
client_port = 49301
server_port = 445
tcp_profile = "nonexistent_profile"
""",
        )


def test_flow_references_unknown_asset_raises(tmp_path):
    """Cross-ref: flow that references an unknown asset slug raises ManifestValidationError."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[[flows]]
type      = "llmnr_query"
client    = "no_such_asset"
qname     = "PACSARCH01"
emit_at_s = 30.0
""",
        )


def test_dhcp_server_slug_not_resolved_raises(tmp_path):
    """Cross-ref: scenario.network.dhcp_server_slug must point to an existing asset."""
    content = _BASE.replace('dhcp_server_slug = "srv"', 'dhcp_server_slug = "missing"')
    with pytest.raises(ManifestValidationError):
        _load_toml(tmp_path, content)


def test_gateway_slug_not_resolved_raises(tmp_path):
    """Cross-ref: scenario.network.gateway_slug must point to an existing asset."""
    content = _BASE.replace('gateway_slug     = "gw"', 'gateway_slug     = "missing"')
    with pytest.raises(ManifestValidationError):
        _load_toml(tmp_path, content)


# ── REQ-EXT extensibility ─────────────────────────────────────────────────────


def test_extra_key_in_dhcp_subtable_accepted(tmp_path):
    """REQ-EXT-001: extra keys inside [assets.x.dhcp] do not raise an error."""
    m = _load_toml(
        tmp_path,
        _BASE
        + """\

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]

[assets.client.dhcp]
xid_discover       = 0xAABBCCDD
xid_request        = 0xAABBCCD0
future_dhcp_field  = "extension_value"
""",
    )
    assert m.assets["client"].dhcp is not None


def test_extra_key_at_asset_root_raises(tmp_path):
    """REQ-EXT-002: unknown key at [assets.x] root is rejected."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.client]
hostname      = "CLIENT"
category      = "workstation"
mac_oui       = "de:ad:be"
mac           = "de:ad:be:ef:00:01"
ip            = "10.0.0.10"
emits         = []
unknown_field = "forbidden"
""",
        )


# ── REQ-LOD-004 ───────────────────────────────────────────────────────────────


def test_empty_assets_and_flows_valid(tmp_path):
    """REQ-LOD-004: a manifest with only the infrastructure assets and no flows is valid."""
    m = _load_toml(tmp_path, _BASE)
    assert len(m.assets) == 2
    assert m.flows == []


# ── Emits consistency ─────────────────────────────────────────────────────────


def test_emits_declared_but_no_subtable_raises(tmp_path):
    """Asset declares emits=['dhcp'] but provides no [assets.x.dhcp] sub-table → error."""
    with pytest.raises(ManifestValidationError):
        _load_toml(
            tmp_path,
            _BASE
            + """\

[assets.client]
hostname = "CLIENT"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]
# no [assets.client.dhcp] sub-table
""",
        )


# ── Generator smoke test ──────────────────────────────────────────────────────


def test_generator_minimal_manifest(tmp_path):
    """generate_packets() on a minimal 1-asset DHCP manifest returns exactly 4 packets."""
    from tapirxl.fixtures.generator import generate_packets

    m = _load_toml(
        tmp_path,
        """\
[meta]
schema_version = 1
manifest_id    = "mini"
created_at     = 2026-01-01T00:00:00Z

[scenario]
domain              = "MININET"
pcap_base_timestamp = "2026-01-01T00:00:00Z"

[scenario.network]
dhcp_server_slug = "dhcp"
gateway_slug     = "gw"
dns_server_ip    = "10.0.0.1"

[profiles]

[assets.dhcp]
hostname = ""
category = "infrastructure"
mac_oui  = "00:11:22"
mac      = "00:11:22:33:44:55"
ip       = "10.0.0.1"
emits    = []

[assets.gw]
hostname = ""
category = "firewall"
mac_oui  = "00:aa:bb"
mac      = "00:aa:bb:cc:dd:ee"
ip       = "10.0.0.254"
emits    = []

[assets.client]
hostname = "CLIENT01"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]

[assets.client.dhcp]
xid_discover = 0xAABBCCDD
xid_request  = 0xAABBCCD0
emit_at_s    = 0.0
""",
    )
    pkts = generate_packets(m)
    assert len(pkts) == 4  # DISCOVER, OFFER, REQUEST, ACK


def test_generator_timestamps_ordered(tmp_path):
    """Two assets at different emit_at_s produce packets in chronological order."""
    from tapirxl.fixtures.generator import generate_packets

    m = _load_toml(
        tmp_path,
        """\
[meta]
schema_version = 1
manifest_id    = "timing_test"
created_at     = 2026-01-01T00:00:00Z

[scenario]
domain              = "TESTNET"
pcap_base_timestamp = "2026-01-01T00:00:00Z"

[scenario.network]
dhcp_server_slug = "dhcp"
gateway_slug     = "gw"
dns_server_ip    = "10.0.0.1"

[profiles]

[assets.dhcp]
hostname = ""
category = "infrastructure"
mac_oui  = "00:11:22"
mac      = "00:11:22:33:44:55"
ip       = "10.0.0.1"
emits    = []

[assets.gw]
hostname = ""
category = "firewall"
mac_oui  = "00:aa:bb"
mac      = "00:aa:bb:cc:dd:ee"
ip       = "10.0.0.254"
emits    = []

[assets.early]
hostname = "EARLY"
category = "workstation"
mac_oui  = "aa:bb:cc"
mac      = "aa:bb:cc:00:00:01"
ip       = "10.0.0.20"
emits    = ["dhcp"]

[assets.early.dhcp]
xid_discover = 0x11111111
xid_request  = 0x11111112
emit_at_s    = 0.0

[assets.late]
hostname = "LATE"
category = "workstation"
mac_oui  = "aa:bb:cc"
mac      = "aa:bb:cc:00:00:02"
ip       = "10.0.0.21"
emits    = ["dhcp"]

[assets.late.dhcp]
xid_discover = 0x22222221
xid_request  = 0x22222222
emit_at_s    = 5.0
""",
    )
    pkts = generate_packets(m)
    # 8 packets total (4 DORA x 2 assets)
    assert len(pkts) == 8
    # Timestamps must be non-decreasing
    times = [pkt.time for pkt in pkts]
    assert times == sorted(times)
    # The early packet's time must be strictly before the late packet's time
    assert pkts[0].time < pkts[4].time


def test_apply_timestamps_negative_emit_at_s(tmp_path):
    """emit_at_s = -1.0 must not collide with the bucket sentinel."""
    from tapirxl.fixtures.generator import generate_packets

    m = _load_toml(
        tmp_path,
        """\
[meta]
schema_version = 1
manifest_id    = "negative_emit"
created_at     = 2026-01-01T00:00:00Z

[scenario]
domain              = "MININET"
pcap_base_timestamp = "2026-01-01T00:00:00Z"
intra_flow_step_s   = 0.00001

[scenario.network]
dhcp_server_slug = "dhcp"
gateway_slug     = "gw"
dns_server_ip    = "10.0.0.1"

[profiles]

[assets.dhcp]
hostname = ""
category = "infrastructure"
mac_oui  = "00:11:22"
mac      = "00:11:22:33:44:55"
ip       = "10.0.0.1"
emits    = []

[assets.gw]
hostname = ""
category = "firewall"
mac_oui  = "00:aa:bb"
mac      = "00:aa:bb:cc:dd:ee"
ip       = "10.0.0.254"
emits    = []

[assets.client]
hostname = "CLIENT01"
category = "workstation"
mac_oui  = "de:ad:be"
mac      = "de:ad:be:ef:00:01"
ip       = "10.0.0.10"
emits    = ["dhcp"]

[assets.client.dhcp]
xid_discover = 0xAABBCCDD
xid_request  = 0xAABBCCD0
emit_at_s    = -1.0
""",
    )
    pkts = generate_packets(m)
    assert len(pkts) == 4
    base_ts = m.scenario.pcap_base_timestamp.timestamp()
    step = m.scenario.intra_flow_step_s
    assert pkts[0].time == pytest.approx(base_ts + (-1.0))
    assert pkts[1].time == pytest.approx(base_ts + (-1.0 + step))
