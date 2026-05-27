"""TLS ClientHello emitter (TCP 3WHS + single ClientHello PDU)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from tapirxl.fixtures.protocols._helpers import (
    TcpState,
    tcp_psh_exchange,
    tcp_three_way_hs,
    tls_client_hello_plaintext,
)

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import FlowTlsClientHello, SignalManifest

_TLS_HTTPS_PORT = 443


def emit_flow(flow: FlowTlsClientHello, manifest: SignalManifest) -> Iterable[tuple[float, object]]:
    client = manifest.assets[flow.client]
    relay = manifest.assets[flow.server_mac_via]
    sport = flow.client_port

    init = TcpState(
        cli_seq=0x7E110000 + (sport & 0xFFFF),
        srv_seq=0x7E220000 + (sport & 0xFFFF),
        client_mac=client.mac,
        server_mac=relay.mac,  # L2 next-hop is the relay (gateway)
        client_ip=client.ip,
        server_ip=flow.server_ip,
        client_port=sport,
        server_port=_TLS_HTTPS_PORT,
        client_ttl=128,
        server_ttl=128,
    )
    hs, tcpst = tcp_three_way_hs(init, sport, _TLS_HTTPS_PORT)
    seg, _ = tcp_psh_exchange(
        sender="client",
        tcpst=tcpst,
        pdu=tls_client_hello_plaintext(flow.sni),
    )
    for pkt in [*hs, *seg]:
        yield (flow.emit_at_s, pkt)
