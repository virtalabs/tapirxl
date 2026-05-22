"""WS-Discovery Hello emitter for solo asset signals."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from tapirxl.fixtures.protocols._helpers import _eth_ip_udp

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import Asset, SignalManifest


def emit_solo(asset: Asset, manifest: SignalManifest) -> Iterable[tuple[float, object]]:
    cfg = asset.wsdiscovery
    if cfg is None:
        return
    body = _soap_body(cfg.uuid, cfg.types).encode("utf-8")
    pkt = _eth_ip_udp(
        ether_src=asset.mac,
        ether_dst="01:00:5e:7f:ff:fa",
        ip_src=asset.ip,
        ip_dst="239.255.255.250",
        udp_sport=3702,
        udp_dport=3702,
        payload=body,
        ip_ttl=1,
    )
    yield (cfg.emit_at_s, pkt)


def _soap_body(uuid: str, types: list[str]) -> str:
    ws_types_nl = "".join(t + "\n" for t in types)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap12:Header/>
  <soap12:Body>
    <wsd:Hello>
      <wsa:EndpointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <wsa:Address>urn:uuid:{uuid}</wsa:Address>
      </wsa:EndpointReference>
      <wsd:Types>{ws_types_nl}</wsd:Types>
    </wsd:Hello>
  </soap12:Body>
</soap12:Envelope>"""
