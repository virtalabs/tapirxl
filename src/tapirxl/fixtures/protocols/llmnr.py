"""LLMNR query / response emitters."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import Asset, FlowLlmnrQuery, SignalManifest

_LLMNR_MCAST_MAC = "01:00:5e:00:00:fc"
_LLMNR_MCAST_IP = "224.0.0.252"
_LLMNR_PORT = 5355


def emit_solo_response(asset: Asset, manifest: SignalManifest) -> Iterable[tuple[float, object]]:
    """Yield a single LLMNR response broadcasting the asset's own hostname."""
    cfg = asset.llmnr_response
    if cfg is None or not asset.hostname:
        return
    yield (cfg.emit_at_s, _llmnr_response(asset.mac, asset.ip, asset.hostname))


def emit_query_flow(
    flow: FlowLlmnrQuery, manifest: SignalManifest
) -> Iterable[tuple[float, object]]:
    """Yield a single LLMNR query from *client* for *qname*."""
    client = manifest.assets[flow.client]
    yield (flow.emit_at_s, _llmnr_query(client.mac, client.ip, flow.qname))


def _llmnr_query(mac: str, ip: str, qname: str) -> object:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    dns = DNS(
        id=0x7AA1,
        qr=0,
        opcode=0,
        aa=0,
        tc=0,
        rd=0,
        ra=0,
        z=0,
        ad=0,
        cd=0,
        rcode=0,
        qd=DNSQR(qname=qname, qtype="A"),
    )
    return (
        Ether(src=mac, dst=_LLMNR_MCAST_MAC)
        / IP(src=ip, dst=_LLMNR_MCAST_IP, ttl=255)
        / UDP(sport=_LLMNR_PORT, dport=_LLMNR_PORT)
        / dns
    )


def _llmnr_response(mac: str, ip: str, resp_name: str) -> object:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    dns = DNS(
        id=0x7AA2,
        qr=1,
        opcode=0,
        aa=1,
        tc=0,
        rd=0,
        ra=0,
        z=0,
        ad=0,
        cd=0,
        rcode=0,
        qd=DNSQR(qname=resp_name, qtype="A"),
        an=DNSRR(rrname=resp_name, type="A", ttl=30, rdata=ip),
    )
    return (
        Ether(src=mac, dst=_LLMNR_MCAST_MAC)
        / IP(src=ip, dst=_LLMNR_MCAST_IP, ttl=255)
        / UDP(sport=_LLMNR_PORT, dport=_LLMNR_PORT)
        / dns
    )
