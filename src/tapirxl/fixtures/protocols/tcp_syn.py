"""TCP SYN fingerprint emitter (single outbound SYN)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from tapirxl.fixtures.protocols._helpers import (
    SYN,
    _tcp_eth,
)

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import FlowTcpSyn, SignalManifest


def emit_flow(flow: FlowTcpSyn, manifest: SignalManifest) -> Iterable[tuple[float, object]]:
    """Yield a single SYN packet from client to server."""
    client = manifest.assets[flow.client]
    server = manifest.assets[flow.server]

    # Resolve fingerprint from flow fields (already merged from profile by loader)
    ip_ttl = flow.ip_ttl
    mss = flow.mss
    window = flow.window
    wscale = flow.wscale
    sack = flow.sack_permitted

    tcp_options: list = [
        ("MSS", mss),
        ("NOP", None),
        ("WScale", wscale),
    ]
    if sack:
        tcp_options.append(("SAckOK", b""))
    tcp_options.append(("EOL", None))

    pkt = _tcp_eth(
        ether_src=client.mac,
        ether_dst=server.mac,
        ip_src=client.ip,
        ip_dst=server.ip,
        sport=flow.client_port,
        dport=flow.server_port,
        flags=SYN,
        seq=(0xC7010000 + (flow.client_port & 0xFFFF)) & 0xFFFF_FFFF,
        ack_num=0,
        ip_ttl=ip_ttl,
        tcp_win=window,
        tcp_options=tcp_options,
    )
    yield (flow.emit_at_s, pkt)
