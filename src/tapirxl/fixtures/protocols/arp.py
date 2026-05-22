"""ARP exchange emitter for multi-host flows."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import FlowArpExchange, SignalManifest


def emit_flow(flow: FlowArpExchange, manifest: SignalManifest) -> Iterable[tuple[float, object]]:
    requester = manifest.assets[flow.requester]
    responder = manifest.assets[flow.responder]

    yield (
        flow.emit_at_s,
        _arp_request(
            src_mac=requester.mac,
            src_ip=requester.ip,
            target_ip=responder.ip,
        ),
    )
    yield (
        flow.emit_at_s,
        _arp_reply(
            src_mac=responder.mac,
            src_ip=responder.ip,
            target_mac=requester.mac,
            target_ip=requester.ip,
        ),
    )


def _arp_request(*, src_mac: str, src_ip: str, target_ip: str) -> object:
    from scapy.layers.l2 import ARP, Ether

    return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=src_mac,
        psrc=src_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip,
    )


def _arp_reply(*, src_mac: str, src_ip: str, target_mac: str, target_ip: str) -> object:
    from scapy.layers.l2 import ARP, Ether

    return Ether(src=src_mac, dst=target_mac) / ARP(
        op=2,
        hwsrc=src_mac,
        psrc=src_ip,
        hwdst=target_mac,
        pdst=target_ip,
    )
