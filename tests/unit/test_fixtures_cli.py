"""Unit tests for tapirxl-fixtures CLI."""

from __future__ import annotations

from datetime import UTC, datetime
from textwrap import dedent

import pytest

_MINIMAL_MANIFEST = dedent("""\
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
""")


def test_custom_manifest_and_output(tmp_path, monkeypatch):
    """--manifest and --output produce a PCAP from a user-authored manifest."""
    pytest.importorskip("scapy")
    from scapy.utils import rdpcap

    from tapirxl.fixtures.cli import main

    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "mini.toml"
    manifest_path.write_text(_MINIMAL_MANIFEST)
    output_path = tmp_path / "out.pcap"

    main(["--manifest", str(manifest_path), "--output", str(output_path)])

    assert output_path.exists()
    assert len(rdpcap(str(output_path))) == 4


def test_default_invocation_uses_bundled_manifest(tmp_path, monkeypatch):
    """Default CLI invocation loads bundled signal_manifest.toml and writes a PCAP."""
    pytest.importorskip("scapy")
    from scapy.utils import rdpcap

    from tapirxl.fixtures.cli import main

    monkeypatch.chdir(tmp_path)
    output_path = tmp_path / "tests" / "fixtures" / "synthetic_philips_demo.pcap"

    main([])

    assert output_path.exists()
    assert len(rdpcap(str(output_path))) > 0


def test_seed_time_overrides_pcap_timestamps(tmp_path, monkeypatch):
    """--seed-time shifts packet times without mutating the manifest TOML."""
    pytest.importorskip("scapy")
    from scapy.utils import rdpcap

    from tapirxl.fixtures.cli import main

    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "mini.toml"
    manifest_path.write_text(_MINIMAL_MANIFEST)
    output_path = tmp_path / "out.pcap"

    seed = "2027-06-15T12:00:00Z"
    expected_ts = datetime(2027, 6, 15, 12, 0, 0, tzinfo=UTC).timestamp()

    main(
        [
            "--manifest",
            str(manifest_path),
            "--output",
            str(output_path),
            "--seed-time",
            seed,
        ]
    )

    pkts = rdpcap(str(output_path))
    assert len(pkts) == 4
    assert pkts[0].time == pytest.approx(expected_ts)
