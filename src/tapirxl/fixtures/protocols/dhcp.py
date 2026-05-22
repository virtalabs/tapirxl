"""DHCP DORA emitter for solo asset signals."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from tapirxl.fixtures.protocols._helpers import _mac_to_bootp_hw

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import Asset, SignalManifest


def emit_solo(asset: Asset, manifest: SignalManifest) -> Iterable[tuple[float, object]]:
    """Yield (emit_at_s, packet) for a full DHCP DORA exchange."""
    cfg = asset.dhcp
    if cfg is None:
        return

    prl = cfg.option55_prl
    vci = cfg.option60_vci or ""
    ip_ttl = cfg.ip_ttl
    xid_disc = cfg.xid_discover or 0
    xid_req = cfg.xid_request or 0
    hostname = asset.hostname or ""
    emit_at = cfg.emit_at_s

    net = manifest.scenario.network
    lease = manifest.scenario.dhcp_lease
    dhcp_server = manifest.assets[net.dhcp_server_slug]
    gateway = manifest.assets[net.gateway_slug]

    for pkt in _build_dora(
        client_mac=asset.mac,
        client_ip=asset.ip,
        hostname=hostname,
        xid_discover=xid_disc,
        xid_request=xid_req,
        vendor_class_id=vci,
        param_req_list=prl or [],
        ip_ttl=ip_ttl,
        server_mac=dhcp_server.mac,
        server_ip=dhcp_server.ip,
        gateway_ip=gateway.ip,
        dns_server_ip=net.dns_server_ip,
        subnet_mask=net.subnet_mask,
        lease_seconds=lease.lease_seconds,
        t1_seconds=lease.t1_seconds,
        t2_seconds=lease.t2_seconds,
    ):
        yield (emit_at, pkt)


def _build_dora(
    *,
    client_mac: str,
    client_ip: str,
    hostname: str,
    xid_discover: int,
    xid_request: int,
    vendor_class_id: str,
    param_req_list: list[int],
    ip_ttl: int,
    server_mac: str,
    server_ip: str,
    gateway_ip: str,
    dns_server_ip: str,
    subnet_mask: str,
    lease_seconds: int,
    t1_seconds: int,
    t2_seconds: int,
) -> list[object]:
    return [
        _dhcp_discover(
            client_mac,
            xid=xid_discover,
            hostname=hostname,
            vendor_class_id=vendor_class_id,
            param_req_list=param_req_list,
            ip_ttl=ip_ttl,
        ),
        _dhcp_server_reply(
            msg_type="offer",
            xid=xid_discover,
            client_mac=client_mac,
            yiaddr=client_ip,
            hostname=hostname,
            server_mac=server_mac,
            server_ip=server_ip,
            gateway_ip=gateway_ip,
            dns_server_ip=dns_server_ip,
            subnet_mask=subnet_mask,
            lease_seconds=lease_seconds,
            t1_seconds=t1_seconds,
            t2_seconds=t2_seconds,
        ),
        _dhcp_request(
            client_mac,
            client_ip,
            xid=xid_request,
            hostname=hostname,
            vendor_class_id=vendor_class_id,
            param_req_list=param_req_list,
            ip_ttl=ip_ttl,
        ),
        _dhcp_server_reply(
            msg_type="ack",
            xid=xid_request,
            client_mac=client_mac,
            yiaddr=client_ip,
            hostname=hostname,
            server_mac=server_mac,
            server_ip=server_ip,
            gateway_ip=gateway_ip,
            dns_server_ip=dns_server_ip,
            subnet_mask=subnet_mask,
            lease_seconds=lease_seconds,
            t1_seconds=t1_seconds,
            t2_seconds=t2_seconds,
        ),
    ]


def _dhcp_discover(
    mac: str,
    *,
    xid: int,
    hostname: str,
    vendor_class_id: str,
    param_req_list: list[int],
    ip_ttl: int,
) -> object:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    boots = BOOTP(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0, flags=0)
    boots.chaddr = _mac_to_bootp_hw(mac)
    opts: list = [
        ("message-type", "discover"),
        ("hostname", hostname),
    ]
    if vendor_class_id:
        opts.append(("vendor_class_id", vendor_class_id))
    opts.append(("param_req_list", param_req_list))
    opts.append("end")
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255", ttl=ip_ttl)
        / UDP(sport=68, dport=67)
        / boots
        / DHCP(options=opts)
    )


def _dhcp_request(
    mac: str,
    requested_ip: str,
    *,
    xid: int,
    hostname: str,
    vendor_class_id: str,
    param_req_list: list[int],
    ip_ttl: int,
) -> object:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    boots = BOOTP(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=2, flags=0)
    boots.chaddr = _mac_to_bootp_hw(mac)
    opts: list = [
        ("message-type", "request"),
        ("hostname", hostname),
    ]
    if vendor_class_id:
        opts.append(("vendor_class_id", vendor_class_id))
    opts += [
        ("requested_addr", requested_ip),
        ("param_req_list", param_req_list),
        "end",
    ]
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255", ttl=ip_ttl)
        / UDP(sport=68, dport=67)
        / boots
        / DHCP(options=opts)
    )


def _dhcp_server_reply(
    *,
    msg_type: str,
    xid: int,
    client_mac: str,
    yiaddr: str,
    hostname: str,
    server_mac: str,
    server_ip: str,
    gateway_ip: str,
    dns_server_ip: str,
    subnet_mask: str,
    lease_seconds: int,
    t1_seconds: int,
    t2_seconds: int,
) -> object:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    boots = BOOTP(
        op=2,
        htype=1,
        hlen=6,
        hops=0,
        xid=xid,
        secs=0,
        flags=0,
        yiaddr=yiaddr,
        siaddr=server_ip,
    )
    boots.chaddr = _mac_to_bootp_hw(client_mac)
    reply = DHCP(
        options=[
            ("message-type", msg_type),
            ("server_id", server_ip),
            ("lease_time", lease_seconds),
            ("renewal_time", t1_seconds),
            ("rebinding_time", t2_seconds),
            ("subnet_mask", subnet_mask),
            ("router", gateway_ip),
            ("name_server", dns_server_ip),
            ("hostname", hostname),
            "end",
        ]
    )
    return (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=yiaddr, ttl=128)
        / UDP(sport=67, dport=68)
        / boots
        / reply
    )
