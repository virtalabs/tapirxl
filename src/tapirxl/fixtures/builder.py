"""Packet builder functions for the synthetic Philips demo PCAP.

All scapy / pydicom / pynetdicom imports are deferred inside functions so that
importing this module does not require those packages to be installed.
"""

from __future__ import annotations

import codecs
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Literal

from tapirxl.fixtures.topology import (
    ACMEWS02,
    BRILLIANCE,
    BRILLIANCE_IMPL_UID,
    BRILLIANCE_IMPL_VER,
    CALLED_CC_AE_TITLE,
    CALLING_CT_AE_TITLE,
    CCPLATFORM,
    CCPLATFORM_IMPL_UID,
    CCPLATFORM_IMPL_VER,
    CT_IMAGE_STORAGE,
    DHCP_OPTIONS_PRL,
    DHCP_SERVER,
    DICOM_MESSAGE_ID,
    DICOM_TCP_PORT,
    DOMAIN_NAME,
    GATEWAY,
    INTELLIVUE,
    MAXIMUM_PDV_LENGTH_BYTES,
    PACSARCH01,
    SOP_INSTANCE_UID_STR,
    TLS_HTTPS_PORT,
    TLS_MICROSOFT,
    TLS_SENTINELONE,
    WIN7_CONSOLE,
    WIN7_DHCP_PRL,
    WIN10_DHCP_PRL,
    WS_DISCOVERY_UUID,
    WS_TYPES,
)

# ── DHCP constants ────────────────────────────────────────────────────────────

DHCP_LEASE_SECONDS = 86_400
DHCP_T1_SECONDS = 43_200
DHCP_T2_SECONDS = 75_600
DHCP_SUBNET_MASK = "255.255.255.0"
DHCP_DNS_SERVER = DHCP_SERVER["ip"]

INTELLIVUE_DHCP_XID_DISCOVER = 0xAABBCCDD
INTELLIVUE_DHCP_XID_REQUEST = 0xAABBCCD0
WIN7_DHCP_XID_DISCOVER = 0x77AABB01
WIN7_DHCP_XID_REQUEST = 0x77AABB02

BRILLIANCE_DHCP_XID_DISCOVER = 0x33CC0001
BRILLIANCE_DHCP_XID_REQUEST = 0x33CC0002
CCPLATFORM_DHCP_XID_DISCOVER = 0x44DD0001
CCPLATFORM_DHCP_XID_REQUEST = 0x44DD0002
ACMEWS02_DHCP_XID_DISCOVER = 0x55EE0001
ACMEWS02_DHCP_XID_REQUEST = 0x55EE0002
PACSARCH01_DHCP_XID_DISCOVER = 0x66FF0001
PACSARCH01_DHCP_XID_REQUEST = 0x66FF0002

# ── TCP flags ─────────────────────────────────────────────────────────────────

SYN = 0x002
SYN_ACK = SYN | 0x010
ACK = 0x010
PSH_ACK = 0x008 | ACK
FIN_ACK = 0x001 | ACK

# Windows 7 SP1 TCP SYN options
_WIN7_SYN_OPTS = [
    ("MSS", 1460),
    ("NOP", None),
    ("WScale", 8),
    ("SAckOK", b""),
    ("EOL", None),
]

# ── NTLMSSP constants ─────────────────────────────────────────────────────────

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLM_TYPE1_NEGOTIATE = 1
NTLM_TYPE2_CHALLENGE = 2
NTLM_TYPE3_AUTHENTICATE = 3

NTLM_NEG_FLAGS_BASE = (
    0x00000001  # Negotiate Unicode
    | 0x00000200  # Negotiate NTLM
    | 0x00010000  # Negotiate Sign (cosmetic)
    | 0x00020000  # Negotiate Always Sign
    | 0x00080000  # Negotiate NTLM2 Key
    | 0x00800000  # Negotiate Target Info
    | 0x02000000  # Negotiate Version
    | 0x80000000  # Negotiate 56
)

NTLMSSP_VERSION = b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"  # Win 6.1 SP1 build 7601

# ── Scenario timing ───────────────────────────────────────────────────────────

SCENARIO_OFFSETS_S: dict[str, float] = {
    "intellivue": 0.0,
    "brilliance_dhcp": 5.0,
    "brilliance": 15.0,
    "win7": 30.0,
    "ccplatform": 45.0,
    "acmews02": 55.0,
    "pacsarch01": 65.0,
}

INTRA_FLOW_STEP_S = 10_000 / 1_000_000_000  # 10 µs


# ── TcpState ──────────────────────────────────────────────────────────────────


@dataclass
class TcpState:
    cli_seq: int
    srv_seq: int
    client_mac: str
    server_mac: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_ttl: int = 128
    server_ttl: int = 128


# ── Low-level packet helpers ──────────────────────────────────────────────────


def _mac_to_bootp_hw(mac_colon: str) -> bytes:
    h = codecs.decode(mac_colon.replace(":", ""), "hex")
    return (h + b"\x00" * 10)[:16]


def _eth_ip_udp(
    *,
    ether_src: str,
    ether_dst: str,
    ip_src: str,
    ip_dst: str,
    udp_sport: int,
    udp_dport: int,
    payload: bytes,
) -> object:
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether
    except ImportError as exc:
        raise SystemExit("Install scapy: pip install scapy") from exc

    return Ether(src=ether_src, dst=ether_dst) / IP(
        src=ip_src, dst=ip_dst, ttl=1 if ip_dst.startswith("239.") else 64
    ) / UDP(sport=udp_sport, dport=udp_dport) / payload


def _tcp_eth(
    *,
    ether_src: str,
    ether_dst: str,
    ip_src: str,
    ip_dst: str,
    sport: int,
    dport: int,
    flags: int,
    seq: int,
    ack_num: int,
    payload: bytes = b"",
    ip_ttl: int = 64,
    tcp_win: int | None = None,
    tcp_options: list | tuple | None = None,
) -> object:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    opts = list(tcp_options) if tcp_options is not None else [("MSS", 1460)]
    tkw: dict = {
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack_num,
        "flags": flags,
        "options": opts,
    }
    if tcp_win is not None:
        tkw["window"] = tcp_win
    t = TCP(**tkw)

    pkt = Ether(src=ether_src, dst=ether_dst) / IP(src=ip_src, dst=ip_dst, ttl=ip_ttl) / t
    if payload:
        pkt = pkt / payload
    return pkt


def _nbss_session_message_payload(smb_payload: bytes) -> bytes:
    length = len(smb_payload)
    return b"\x00" + struct.pack("!I", length)[1:] + smb_payload


def _sec_buffer(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def _av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


# ── WS-Discovery ──────────────────────────────────────────────────────────────


def ws_discovery_soap_body() -> str:
    urn = WS_DISCOVERY_UUID
    ws_types_nl = "".join(t + "\n" for t in WS_TYPES)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap12:Header/>
  <soap12:Body>
    <wsd:Hello>
      <wsa:EndpointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
        <wsa:Address>urn:uuid:{urn}</wsa:Address>
      </wsa:EndpointReference>
      <wsd:Types>{ws_types_nl}</wsd:Types>
    </wsd:Hello>
  </soap12:Body>
</soap12:Envelope>"""


def build_wsdiscovery_hello(mac: str, ip_src: str) -> object:
    body = ws_discovery_soap_body().encode("utf-8")
    return _eth_ip_udp(
        ether_src=mac,
        ether_dst="01:00:5e:7f:ff:fa",
        ip_src=ip_src,
        ip_dst="239.255.255.250",
        udp_sport=3702,
        udp_dport=3702,
        payload=body,
    )


# ── DHCP ──────────────────────────────────────────────────────────────────────


def build_dhcp_discover(
    mac: str,
    *,
    xid: int = 0xAABBCCDD,
    hostname: str = "MX700-bed12",
    vendor_class_id: str = "Philips IntelliVue",
    param_req_list: list[int] | None = None,
    ip_ttl: int = 64,
) -> object:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    prl = param_req_list if param_req_list is not None else DHCP_OPTIONS_PRL
    boots = BOOTP(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=0, flags=0)
    boots.chaddr = _mac_to_bootp_hw(mac)
    dhcp_disc = DHCP(
        options=[
            ("message-type", "discover"),
            ("hostname", hostname),
            ("vendor_class_id", vendor_class_id),
            ("param_req_list", prl),
            "end",
        ]
    )
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255", ttl=ip_ttl)
        / UDP(sport=68, dport=67)
        / boots
        / dhcp_disc
    )


def build_dhcp_request(
    mac: str,
    requested_ip: str,
    *,
    xid: int = 0xAABBCCD0,
    hostname: str = "MX700-bed12",
    vendor_class_id: str = "Philips IntelliVue",
    param_req_list: list[int] | None = None,
    ip_ttl: int = 64,
) -> object:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    prl = param_req_list if param_req_list is not None else DHCP_OPTIONS_PRL
    boots = BOOTP(op=1, htype=1, hlen=6, hops=0, xid=xid, secs=2, flags=0)
    boots.chaddr = _mac_to_bootp_hw(mac)
    dhcp_rq = DHCP(
        options=[
            ("message-type", "request"),
            ("hostname", hostname),
            ("vendor_class_id", vendor_class_id),
            ("requested_addr", requested_ip),
            ("param_req_list", prl),
            "end",
        ]
    )
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255", ttl=ip_ttl)
        / UDP(sport=68, dport=67)
        / boots
        / dhcp_rq
    )


def _dhcp_server_reply(
    *,
    msg_type: str,
    xid: int,
    client_mac: str,
    yiaddr: str,
    hostname: str,
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
        siaddr=DHCP_SERVER["ip"],
    )
    boots.chaddr = _mac_to_bootp_hw(client_mac)
    reply = DHCP(
        options=[
            ("message-type", msg_type),
            ("server_id", DHCP_SERVER["ip"]),
            ("lease_time", DHCP_LEASE_SECONDS),
            ("renewal_time", DHCP_T1_SECONDS),
            ("rebinding_time", DHCP_T2_SECONDS),
            ("subnet_mask", DHCP_SUBNET_MASK),
            ("router", GATEWAY["ip"]),
            ("name_server", DHCP_DNS_SERVER),
            ("hostname", hostname),
            "end",
        ]
    )
    return (
        Ether(src=DHCP_SERVER["mac"], dst=client_mac)
        / IP(src=DHCP_SERVER["ip"], dst=yiaddr, ttl=128)
        / UDP(sport=67, dport=68)
        / boots
        / reply
    )


def build_dhcp_offer(
    *, client_mac: str, offered_ip: str, xid: int, hostname: str
) -> object:
    return _dhcp_server_reply(
        msg_type="offer",
        xid=xid,
        client_mac=client_mac,
        yiaddr=offered_ip,
        hostname=hostname,
    )


def build_dhcp_ack(
    *, client_mac: str, offered_ip: str, xid: int, hostname: str
) -> object:
    return _dhcp_server_reply(
        msg_type="ack",
        xid=xid,
        client_mac=client_mac,
        yiaddr=offered_ip,
        hostname=hostname,
    )


def build_dora_for(
    host: dict,
    *,
    discover_xid: int,
    request_xid: int,
    vendor_class_id: str,
    param_req_list: list[int] | None = None,
    ip_ttl: int = 64,
) -> list[object]:
    """Full DHCP DORA: client DISCOVER, server OFFER, client REQUEST, server ACK."""
    return [
        build_dhcp_discover(
            host["mac"],
            xid=discover_xid,
            hostname=host["name"],
            vendor_class_id=vendor_class_id,
            param_req_list=param_req_list,
            ip_ttl=ip_ttl,
        ),
        build_dhcp_offer(
            client_mac=host["mac"],
            offered_ip=host["ip"],
            xid=discover_xid,
            hostname=host["name"],
        ),
        build_dhcp_request(
            host["mac"],
            host["ip"],
            xid=request_xid,
            hostname=host["name"],
            vendor_class_id=vendor_class_id,
            param_req_list=param_req_list,
            ip_ttl=ip_ttl,
        ),
        build_dhcp_ack(
            client_mac=host["mac"],
            offered_ip=host["ip"],
            xid=request_xid,
            hostname=host["name"],
        ),
    ]


def build_dhcp_discover_win7(host: dict) -> object:
    return build_dhcp_discover(
        host["mac"],
        xid=WIN7_DHCP_XID_DISCOVER,
        hostname=host["name"],
        vendor_class_id="MSFT 5.0",
        param_req_list=WIN7_DHCP_PRL,
        ip_ttl=128,
    )


def build_dhcp_request_win7(host: dict, requested_ip: str) -> object:
    return build_dhcp_request(
        host["mac"],
        requested_ip,
        xid=WIN7_DHCP_XID_REQUEST,
        hostname=host["name"],
        vendor_class_id="MSFT 5.0",
        param_req_list=WIN7_DHCP_PRL,
        ip_ttl=128,
    )


# ── ARP ───────────────────────────────────────────────────────────────────────


def build_arp_request(*, src_mac: str, src_ip: str, target_ip: str) -> object:
    from scapy.layers.l2 import ARP, Ether

    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=src_mac,
            psrc=src_ip,
            hwdst="00:00:00:00:00:00",
            pdst=target_ip,
        )
    )


def build_arp_reply(
    *, src_mac: str, src_ip: str, target_mac: str, target_ip: str
) -> object:
    from scapy.layers.l2 import ARP, Ether

    return (
        Ether(src=src_mac, dst=target_mac)
        / ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=target_mac, pdst=target_ip)
    )


def build_arp_exchange(requester: dict, responder: dict) -> list[object]:
    return [
        build_arp_request(
            src_mac=requester["mac"],
            src_ip=requester["ip"],
            target_ip=responder["ip"],
        ),
        build_arp_reply(
            src_mac=responder["mac"],
            src_ip=responder["ip"],
            target_mac=requester["mac"],
            target_ip=requester["ip"],
        ),
    ]


# ── TCP ───────────────────────────────────────────────────────────────────────


def tcp_three_way_hs(
    st: TcpState, sport: int, dport: int
) -> tuple[list[object], TcpState]:
    seq_b = st.cli_seq
    seq_c = st.srv_seq

    pkts = [
        _tcp_eth(
            ether_src=st.client_mac,
            ether_dst=st.server_mac,
            ip_src=st.client_ip,
            ip_dst=st.server_ip,
            sport=sport,
            dport=dport,
            flags=SYN,
            seq=seq_b,
            ack_num=0,
            ip_ttl=st.client_ttl,
        ),
        _tcp_eth(
            ether_src=st.server_mac,
            ether_dst=st.client_mac,
            ip_src=st.server_ip,
            ip_dst=st.client_ip,
            sport=dport,
            dport=sport,
            flags=SYN_ACK,
            seq=seq_c,
            ack_num=seq_b + 1,
            ip_ttl=st.server_ttl,
        ),
        _tcp_eth(
            ether_src=st.client_mac,
            ether_dst=st.server_mac,
            ip_src=st.client_ip,
            ip_dst=st.server_ip,
            sport=sport,
            dport=dport,
            flags=ACK,
            seq=seq_b + 1,
            ack_num=seq_c + 1,
            ip_ttl=st.client_ttl,
        ),
    ]
    next_st = TcpState(
        cli_seq=seq_b + 1,
        srv_seq=seq_c + 1,
        client_mac=st.client_mac,
        server_mac=st.server_mac,
        client_ip=st.client_ip,
        server_ip=st.server_ip,
        client_port=sport,
        server_port=dport,
        client_ttl=st.client_ttl,
        server_ttl=st.server_ttl,
    )
    return pkts, next_st


def tcp_psh_exchange(
    *,
    sender: Literal["client", "server"],
    tcpst: TcpState,
    pdu: bytes,
) -> tuple[list[object], TcpState]:
    pkts: list[object] = []
    if sender == "client":
        ether_src = tcpst.client_mac
        ether_dst = tcpst.server_mac
        ip_src = tcpst.client_ip
        ip_dst = tcpst.server_ip
        sport = tcpst.client_port
        dport = tcpst.server_port
        seq_here = tcpst.cli_seq
        ack_peer = tcpst.srv_seq
        next_cli = tcpst.cli_seq + len(pdu)
        next_srv = tcpst.srv_seq
        sender_ttl = tcpst.client_ttl
    else:
        ether_src = tcpst.server_mac
        ether_dst = tcpst.client_mac
        ip_src = tcpst.server_ip
        ip_dst = tcpst.client_ip
        sport = tcpst.server_port
        dport = tcpst.client_port
        seq_here = tcpst.srv_seq
        ack_peer = tcpst.cli_seq
        next_srv = tcpst.srv_seq + len(pdu)
        next_cli = tcpst.cli_seq
        sender_ttl = tcpst.server_ttl

    pkts.append(
        _tcp_eth(
            ether_src=ether_src,
            ether_dst=ether_dst,
            ip_src=ip_src,
            ip_dst=ip_dst,
            sport=sport,
            dport=dport,
            flags=PSH_ACK,
            seq=seq_here,
            ack_num=ack_peer,
            payload=pdu,
            ip_ttl=sender_ttl,
        )
    )

    if sender == "client":
        peer_seq = tcpst.srv_seq
        peer_ack = next_cli
        pkts.append(
            _tcp_eth(
                ether_src=tcpst.server_mac,
                ether_dst=tcpst.client_mac,
                ip_src=tcpst.server_ip,
                ip_dst=tcpst.client_ip,
                sport=tcpst.server_port,
                dport=tcpst.client_port,
                flags=ACK,
                seq=peer_seq,
                ack_num=peer_ack,
                ip_ttl=tcpst.server_ttl,
            )
        )
        new_st = TcpState(
            cli_seq=next_cli,
            srv_seq=peer_seq,
            client_mac=tcpst.client_mac,
            server_mac=tcpst.server_mac,
            client_ip=tcpst.client_ip,
            server_ip=tcpst.server_ip,
            client_port=tcpst.client_port,
            server_port=tcpst.server_port,
            client_ttl=tcpst.client_ttl,
            server_ttl=tcpst.server_ttl,
        )
    else:
        peer_seq = tcpst.cli_seq
        peer_ack = next_srv
        pkts.append(
            _tcp_eth(
                ether_src=tcpst.client_mac,
                ether_dst=tcpst.server_mac,
                ip_src=tcpst.client_ip,
                ip_dst=tcpst.server_ip,
                sport=tcpst.client_port,
                dport=tcpst.server_port,
                flags=ACK,
                seq=peer_seq,
                ack_num=peer_ack,
                ip_ttl=tcpst.client_ttl,
            )
        )
        new_st = TcpState(
            cli_seq=peer_seq,
            srv_seq=next_srv,
            client_mac=tcpst.client_mac,
            server_mac=tcpst.server_mac,
            client_ip=tcpst.client_ip,
            server_ip=tcpst.server_ip,
            client_port=tcpst.client_port,
            server_port=tcpst.server_port,
            client_ttl=tcpst.client_ttl,
            server_ttl=tcpst.server_ttl,
        )

    return pkts, new_st


def tcp_fin_teardown(tcpst: TcpState) -> list[object]:
    return [
        _tcp_eth(
            ether_src=tcpst.client_mac,
            ether_dst=tcpst.server_mac,
            ip_src=tcpst.client_ip,
            ip_dst=tcpst.server_ip,
            sport=tcpst.client_port,
            dport=tcpst.server_port,
            flags=FIN_ACK,
            seq=tcpst.cli_seq,
            ack_num=tcpst.srv_seq,
            ip_ttl=tcpst.client_ttl,
        ),
        _tcp_eth(
            ether_src=tcpst.server_mac,
            ether_dst=tcpst.client_mac,
            ip_src=tcpst.server_ip,
            ip_dst=tcpst.client_ip,
            sport=tcpst.server_port,
            dport=tcpst.client_port,
            flags=ACK,
            seq=tcpst.srv_seq,
            ack_num=tcpst.cli_seq + 1,
            ip_ttl=tcpst.server_ttl,
        ),
        _tcp_eth(
            ether_src=tcpst.server_mac,
            ether_dst=tcpst.client_mac,
            ip_src=tcpst.server_ip,
            ip_dst=tcpst.client_ip,
            sport=tcpst.server_port,
            dport=tcpst.client_port,
            flags=FIN_ACK,
            seq=tcpst.srv_seq,
            ack_num=tcpst.cli_seq + 1,
            ip_ttl=tcpst.server_ttl,
        ),
        _tcp_eth(
            ether_src=tcpst.client_mac,
            ether_dst=tcpst.server_mac,
            ip_src=tcpst.client_ip,
            ip_dst=tcpst.server_ip,
            sport=tcpst.client_port,
            dport=tcpst.server_port,
            flags=ACK,
            seq=tcpst.cli_seq + 1,
            ack_num=tcpst.srv_seq + 1,
            ip_ttl=tcpst.client_ttl,
        ),
    ]


def build_tcp_syn_windows(
    client: dict,
    server: dict,
    *,
    sport: int,
    dport: int,
) -> object:
    """Single outbound SYN with a Windows-7-like window + option set."""
    return _tcp_eth(
        ether_src=client["mac"],
        ether_dst=server["mac"],
        ip_src=client["ip"],
        ip_dst=server["ip"],
        sport=sport,
        dport=dport,
        flags=SYN,
        seq=(0xC7010000 + (sport & 0xFFFF)) & 0xFFFFFFFF,
        ack_num=0,
        ip_ttl=128,
        tcp_win=8192,
        tcp_options=_WIN7_SYN_OPTS,
    )


# ── TLS ───────────────────────────────────────────────────────────────────────


def _tls_extensions_client_hello(sni: str) -> bytes:
    sni_b = sni.encode("ascii")
    snilist = (
        struct.pack("!H", len(sni_b) + 3)
        + bytes([0x00])
        + struct.pack("!H", len(sni_b))
        + sni_b
    )
    ext_sni = b"\x00\x00" + struct.pack("!H", len(snilist)) + snilist

    groups = bytes.fromhex("001700180019")
    sg_body = struct.pack("!H", len(groups)) + groups
    ext_sg = b"\x00\x0a" + struct.pack("!H", len(sg_body)) + sg_body

    sigs = bytes.fromhex("0401040204010201030305030308030408050405010806040201")
    sig_body = struct.pack("!H", len(sigs)) + sigs
    ext_sig = b"\x00\x0d" + struct.pack("!H", len(sig_body)) + sig_body

    epf_body = bytes([1, 0])
    ext_epf = b"\x00\x0b" + struct.pack("!H", len(epf_body)) + epf_body

    ext_ff = b"\xff\x01" + struct.pack("!H", 1) + b"\x00"

    return ext_sni + ext_sg + ext_sig + ext_epf + ext_ff


def _tls_client_hello_plaintext(sni: str) -> bytes:
    rng = bytes.fromhex("deadbeef" * 8)
    _su_win7_sp1 = (
        0xC027, 0xC028, 0xC02F, 0xC030, 0xC013, 0xC014, 0xC009, 0xC00A,
        0x009C, 0x009D, 0x002F, 0x003C, 0x009E, 0x009F,
        0xCC14, 0xCC13, 0xCC15, 0x0013, 0x0032, 0x0035, 0x005C,
    )
    ciphersuites = b"".join(struct.pack("!H", x) for x in _su_win7_sp1)
    comp = b"\x01\x00"
    exts = _tls_extensions_client_hello(sni)
    ch_body = (
        b"\x03\x03"
        + rng
        + b"\x00"
        + struct.pack("!H", len(ciphersuites))
        + ciphersuites
        + comp
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def build_tls_client_hello(
    client: dict, server: dict, sport: int, sni: str
) -> list[object]:
    init = TcpState(
        cli_seq=0x7E110000 + (sport & 0xFFFF),
        srv_seq=0x7E220000 + (sport & 0xFFFF),
        client_mac=client["mac"],
        server_mac=server["mac"],
        client_ip=client["ip"],
        server_ip=server["ip"],
        client_port=sport,
        server_port=TLS_HTTPS_PORT,
    )
    hs, tcpst = tcp_three_way_hs(init, sport, TLS_HTTPS_PORT)
    seg, _ = tcp_psh_exchange(
        sender="client", tcpst=tcpst, pdu=_tls_client_hello_plaintext(sni)
    )
    return [*hs, *seg]


# ── SMB2 ──────────────────────────────────────────────────────────────────────


def _smb2_sync_header(command: int = 0, message_id: int = 1) -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<H", hdr, 4, 64)
    struct.pack_into("<H", hdr, 6, 0)
    struct.pack_into("<I", hdr, 8, 0)
    struct.pack_into("<H", hdr, 12, command)
    struct.pack_into("<H", hdr, 14, 126)
    struct.pack_into("<I", hdr, 16, 0)
    struct.pack_into("<I", hdr, 20, 0)
    struct.pack_into("<Q", hdr, 24, message_id)
    struct.pack_into("<I", hdr, 32, 0)
    struct.pack_into("<I", hdr, 36, 0)
    struct.pack_into("<Q", hdr, 40, 0)
    return bytes(hdr)


def _smb2_negotiate_request_body() -> bytes:
    client_guid = bytes.fromhex("a1b2c3d4e5f6708190a0b0c0d0e0f101")
    body = struct.pack("<HHHH", 36, 2, 1, 0)
    body += struct.pack("<I", 0)
    body += client_guid
    body += struct.pack("<Q", 0)
    body += struct.pack("<HH", 0x0202, 0x0210)
    return body


def build_smb2_negotiate_request(client: dict, server: dict, sport: int) -> list[object]:
    smb = _smb2_sync_header(0, 1) + _smb2_negotiate_request_body()
    pdu = _nbss_session_message_payload(smb)
    init = TcpState(
        cli_seq=0x7E330000 + (sport & 0xFFFF),
        srv_seq=0x7E440000 + (sport & 0xFFFF),
        client_mac=client["mac"],
        server_mac=server["mac"],
        client_ip=client["ip"],
        server_ip=server["ip"],
        client_port=sport,
        server_port=445,
    )
    hs, tcpst = tcp_three_way_hs(init, sport, 445)
    seg, _ = tcp_psh_exchange(sender="client", tcpst=tcpst, pdu=pdu)
    return [*hs, *seg]


# ── NTLMSSP / SMB2 SESSION SETUP ──────────────────────────────────────────────


def build_ntlmssp_negotiate(domain: str, workstation: str) -> bytes:
    domain_b = domain.encode("ascii", "ignore")
    ws_b = workstation.encode("ascii", "ignore")

    flags = NTLM_NEG_FLAGS_BASE | 0x00001000 | 0x00002000
    header_len = 8 + 4 + 4 + 8 + 8 + 8
    domain_off = header_len
    ws_off = domain_off + len(domain_b)

    out = NTLMSSP_SIGNATURE
    out += struct.pack("<I", NTLM_TYPE1_NEGOTIATE)
    out += struct.pack("<I", flags)
    out += _sec_buffer(len(domain_b), domain_off)
    out += _sec_buffer(len(ws_b), ws_off)
    out += NTLMSSP_VERSION
    out += domain_b + ws_b
    return out


def build_ntlmssp_challenge(target_name: str, domain: str, server_hostname: str) -> bytes:
    target_w = _utf16le(target_name)
    av_dom_w = _utf16le(domain)
    av_srv_w = _utf16le(server_hostname)
    av_dnsdom_w = _utf16le(f"{domain.lower()}.local")
    av_dnssrv_w = _utf16le(f"{server_hostname.lower()}.{domain.lower()}.local")

    av_pairs = (
        _av_pair(0x0002, av_dom_w)      # MsvAvNbDomainName
        + _av_pair(0x0001, av_srv_w)    # MsvAvNbComputerName
        + _av_pair(0x0004, av_dnsdom_w) # MsvAvDnsDomainName
        + _av_pair(0x0003, av_dnssrv_w) # MsvAvDnsComputerName
        + _av_pair(0x0007, b"\x00" * 8) # MsvAvTimestamp
        + _av_pair(0x0000, b"")         # MsvAvEOL
    )

    flags = NTLM_NEG_FLAGS_BASE | 0x00100000
    server_challenge = bytes.fromhex("0123456789abcdef")
    reserved = b"\x00" * 8

    header_len = 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8
    target_off = header_len
    av_off = target_off + len(target_w)

    out = NTLMSSP_SIGNATURE
    out += struct.pack("<I", NTLM_TYPE2_CHALLENGE)
    out += _sec_buffer(len(target_w), target_off)
    out += struct.pack("<I", flags)
    out += server_challenge
    out += reserved
    out += _sec_buffer(len(av_pairs), av_off)
    out += NTLMSSP_VERSION
    out += target_w + av_pairs
    return out


def build_ntlmssp_authenticate(
    *, domain: str, username: str, workstation: str
) -> bytes:
    dom_w = _utf16le(domain)
    user_w = _utf16le(username)
    ws_w = _utf16le(workstation)

    lm_resp = b"\x00" * 24
    nt_resp = b"\x00" * 24
    sess_key = b""

    flags = NTLM_NEG_FLAGS_BASE
    header_len = 8 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 8
    lm_off = header_len
    nt_off = lm_off + len(lm_resp)
    dom_off = nt_off + len(nt_resp)
    user_off = dom_off + len(dom_w)
    ws_off = user_off + len(user_w)
    sk_off = ws_off + len(ws_w)

    out = NTLMSSP_SIGNATURE
    out += struct.pack("<I", NTLM_TYPE3_AUTHENTICATE)
    out += _sec_buffer(len(lm_resp), lm_off)
    out += _sec_buffer(len(nt_resp), nt_off)
    out += _sec_buffer(len(dom_w), dom_off)
    out += _sec_buffer(len(user_w), user_off)
    out += _sec_buffer(len(ws_w), ws_off)
    out += _sec_buffer(len(sess_key), sk_off)
    out += struct.pack("<I", flags)
    out += NTLMSSP_VERSION
    out += lm_resp + nt_resp + dom_w + user_w + ws_w + sess_key
    return out


def _smb2_session_setup_request_body(security_blob: bytes) -> bytes:
    structure_size = 25
    flags = 0
    security_mode = 0x01
    capabilities = 0x00000001
    channel = 0
    sec_offset = 0x58
    sec_length = len(security_blob)
    previous_session_id = 0
    body = struct.pack(
        "<HBBIIHHQ",
        structure_size,
        flags,
        security_mode,
        capabilities,
        channel,
        sec_offset,
        sec_length,
        previous_session_id,
    )
    return body + security_blob


def _smb2_session_setup_response_body(security_blob: bytes) -> bytes:
    structure_size = 9
    session_flags = 0
    sec_offset = 0x48
    sec_length = len(security_blob)
    body = struct.pack("<HHHH", structure_size, session_flags, sec_offset, sec_length)
    return body + security_blob


def build_smb2_session_setup_ntlmssp(
    *,
    client: dict,
    server: dict,
    sport: int,
    client_hostname: str,
    server_hostname: str,
    domain: str,
    username: str = "ctop",
) -> list[object]:
    """Three-leg SMB2 SESSION_SETUP carrying NTLMSSP NEGOTIATE / CHALLENGE / AUTHENTICATE."""
    init = TcpState(
        cli_seq=0x7E550000 + (sport & 0xFFFF),
        srv_seq=0x7E660000 + (sport & 0xFFFF),
        client_mac=client["mac"],
        server_mac=server["mac"],
        client_ip=client["ip"],
        server_ip=server["ip"],
        client_port=sport,
        server_port=445,
    )
    pkts: list[object] = []
    hs, tcpst = tcp_three_way_hs(init, sport, 445)
    pkts.extend(hs)

    neg = build_ntlmssp_negotiate(domain, client_hostname)
    smb_req1 = _smb2_sync_header(command=1, message_id=2) + _smb2_session_setup_request_body(neg)
    seg, tcpst = tcp_psh_exchange(
        sender="client", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_req1)
    )
    pkts.extend(seg)

    chal = build_ntlmssp_challenge(
        target_name=domain, domain=domain, server_hostname=server_hostname
    )
    smb_resp1 = _smb2_sync_header(command=1, message_id=2) + _smb2_session_setup_response_body(chal)
    seg, tcpst = tcp_psh_exchange(
        sender="server", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_resp1)
    )
    pkts.extend(seg)

    auth = build_ntlmssp_authenticate(
        domain=domain, username=username, workstation=client_hostname
    )
    smb_req2 = _smb2_sync_header(command=1, message_id=3) + _smb2_session_setup_request_body(auth)
    seg, tcpst = tcp_psh_exchange(
        sender="client", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_req2)
    )
    pkts.extend(seg)

    smb_resp2 = _smb2_sync_header(command=1, message_id=3) + _smb2_session_setup_response_body(b"")
    seg, _tcpst = tcp_psh_exchange(
        sender="server", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_resp2)
    )
    pkts.extend(seg)

    return pkts


# ── LLMNR ─────────────────────────────────────────────────────────────────────


def build_llmnr_query(client: dict, qname: str) -> object:
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
        Ether(src=client["mac"], dst="01:00:5e:00:00:fc")
        / IP(src=client["ip"], dst="224.0.0.252", ttl=255)
        / UDP(sport=5355, dport=5355)
        / dns
    )


def build_llmnr_response(mac: str, ip_a: str, resp_name: str) -> object:
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
        an=DNSRR(rrname=resp_name, type="A", ttl=30, rdata=ip_a),
    )
    return (
        Ether(src=mac, dst="01:00:5e:00:00:fc")
        / IP(src=ip_a, dst="224.0.0.252", ttl=255)
        / UDP(sport=5355, dport=5355)
        / dns
    )


# ── DICOM ─────────────────────────────────────────────────────────────────────


def _build_a_associate_rq_pdu() -> bytes:
    try:
        from pydicom.uid import UID as _PUID
        from pynetdicom.pdu import A_ASSOCIATE_RQ
        from pynetdicom.pdu_primitives import (
            A_ASSOCIATE as _AA,
        )
        from pynetdicom.pdu_primitives import (
            ImplementationVersionNameNotification as _IVN,
        )
        from pynetdicom.presentation import PresentationContext
    except ImportError as exc:
        raise SystemExit(
            "Install pynetdicom+pydicom: pip install pydicom pynetdicom"
        ) from exc

    from pydicom.uid import ExplicitVRLittleEndian

    cx = PresentationContext()
    cx.context_id = 1
    cx.abstract_syntax = _PUID(CT_IMAGE_STORAGE)
    cx.transfer_syntax = [ExplicitVRLittleEndian]

    assoc = _AA()
    assoc.application_context_name = _PUID("1.2.840.10008.3.1.1.1")
    assoc.calling_ae_title = CALLING_CT_AE_TITLE
    assoc.called_ae_title = CALLED_CC_AE_TITLE
    assoc.presentation_context_definition_list = [cx]
    assoc.maximum_length_received = MAXIMUM_PDV_LENGTH_BYTES
    assoc.implementation_class_uid = _PUID(BRILLIANCE_IMPL_UID)
    ver = _IVN()
    ver.implementation_version_name = BRILLIANCE_IMPL_VER
    assoc.user_information.append(ver)
    return bytes(A_ASSOCIATE_RQ(assoc).encode())


def _build_a_associate_ac_pdu() -> bytes:
    try:
        from pydicom.uid import UID as _PUID
        from pynetdicom.pdu import A_ASSOCIATE_AC
        from pynetdicom.pdu_primitives import (
            A_ASSOCIATE as _AA,
        )
        from pynetdicom.pdu_primitives import (
            ImplementationVersionNameNotification as _IVN,
        )
        from pynetdicom.presentation import PresentationContext
    except ImportError as exc:
        raise SystemExit("Install pynetdicom+pydicom") from exc

    from pydicom.uid import ExplicitVRLittleEndian

    cx = PresentationContext()
    cx.context_id = 1
    cx.abstract_syntax = _PUID(CT_IMAGE_STORAGE)
    cx.transfer_syntax = [ExplicitVRLittleEndian]
    cx.result = 0

    assoc = _AA()
    assoc.result = 0
    assoc.application_context_name = _PUID("1.2.840.10008.3.1.1.1")
    assoc.calling_ae_title = CALLED_CC_AE_TITLE
    assoc.called_ae_title = CALLING_CT_AE_TITLE
    assoc.presentation_context_definition_results_list = [cx]
    assoc.maximum_length_received = MAXIMUM_PDV_LENGTH_BYTES
    assoc.implementation_class_uid = _PUID(CCPLATFORM_IMPL_UID)
    ver = _IVN()
    ver.implementation_version_name = CCPLATFORM_IMPL_VER
    assoc.user_information.append(ver)
    return bytes(A_ASSOCIATE_AC(assoc).encode())


def _pdata_pdus_dimse(
    dimse_rq, cid: int = 1, max_pdu: int = MAXIMUM_PDV_LENGTH_BYTES
) -> list[bytes]:
    try:
        from pynetdicom.pdu import P_DATA_TF
    except ImportError as exc:
        raise SystemExit("pip install pynetdicom") from exc

    out: list[bytes] = []
    for pdata in dimse_rq.encode_msg(cid, max_pdu):
        out.append(bytes(P_DATA_TF(pdata).encode()))
    return out


def _dimse_c_store_rq(message_id: int = DICOM_MESSAGE_ID):
    from pydicom.dataset import Dataset
    from pydicom.uid import UID as _PUID
    from pynetdicom.dimse_messages import C_STORE_RQ
    from pynetdicom.dimse_primitives import C_STORE
    from pynetdicom.dsutils import encode as ds_encode

    ds = Dataset()
    ds.PatientName = "SYNTH^POC"
    ds.Modality = "CT"
    ds.Manufacturer = "Philips"
    ds.ManufacturerModelName = "Brilliance iCT"
    ds.SoftwareVersions = ["4.1.6"]

    prim = C_STORE()
    prim.MessageID = message_id
    prim.AffectedSOPClassUID = _PUID(CT_IMAGE_STORAGE)
    prim.AffectedSOPInstanceUID = _PUID(SOP_INSTANCE_UID_STR)
    blob = ds_encode(ds, False, True)
    prim.DataSet = BytesIO(blob or b"")

    msg = C_STORE_RQ()
    msg.primitive_to_message(prim)
    return msg


def _dimse_c_store_rsp(message_id_being_answered_to: int = DICOM_MESSAGE_ID):
    from pydicom.uid import UID as _PUID
    from pynetdicom.dimse_messages import C_STORE_RSP
    from pynetdicom.dimse_primitives import C_STORE

    prim = C_STORE()
    prim.MessageIDBeingRespondedTo = message_id_being_answered_to
    prim.Status = 0x0000
    prim.AffectedSOPClassUID = _PUID(CT_IMAGE_STORAGE)
    prim.AffectedSOPInstanceUID = _PUID(SOP_INSTANCE_UID_STR)
    rsp = C_STORE_RSP()
    rsp.primitive_to_message(prim)
    return rsp


# ── Scenarios ─────────────────────────────────────────────────────────────────


def scenario_intellivue_mx700() -> list[object]:
    out: list[object] = build_dora_for(
        INTELLIVUE,
        discover_xid=INTELLIVUE_DHCP_XID_DISCOVER,
        request_xid=INTELLIVUE_DHCP_XID_REQUEST,
        vendor_class_id="Philips IntelliVue",
        param_req_list=DHCP_OPTIONS_PRL,
        ip_ttl=64,
    )
    out.append(build_wsdiscovery_hello(INTELLIVUE["mac"], INTELLIVUE["ip"]))
    return out


def scenario_brilliance_dhcp() -> list[object]:
    return build_dora_for(
        BRILLIANCE,
        discover_xid=BRILLIANCE_DHCP_XID_DISCOVER,
        request_xid=BRILLIANCE_DHCP_XID_REQUEST,
        vendor_class_id="Philips Brilliance iCT",
        param_req_list=DHCP_OPTIONS_PRL,
        ip_ttl=64,
    )


def scenario_brilliance_to_ccp() -> list[object]:
    pkts_out: list[object] = []
    sport = 49_152

    pkts_out.extend(build_arp_exchange(BRILLIANCE, CCPLATFORM))

    init = TcpState(
        cli_seq=0x1A001B00,
        srv_seq=0x2F002C00,
        client_mac=BRILLIANCE["mac"],
        server_mac=CCPLATFORM["mac"],
        client_ip=BRILLIANCE["ip"],
        server_ip=CCPLATFORM["ip"],
        client_port=sport,
        server_port=DICOM_TCP_PORT,
    )

    handshake, tcpst = tcp_three_way_hs(init, sport, DICOM_TCP_PORT)
    pkts_out.extend(handshake)

    seg, tcpst = tcp_psh_exchange(
        sender="client", tcpst=tcpst, pdu=_build_a_associate_rq_pdu()
    )
    pkts_out.extend(seg)

    seg, tcpst = tcp_psh_exchange(
        sender="server", tcpst=tcpst, pdu=_build_a_associate_ac_pdu()
    )
    pkts_out.extend(seg)

    cstore_rq = _dimse_c_store_rq()
    for blob in _pdata_pdus_dimse(cstore_rq, cid=1):
        seg, tcpst = tcp_psh_exchange(sender="client", tcpst=tcpst, pdu=blob)
        pkts_out.extend(seg)

    cstore_rs = _dimse_c_store_rsp()
    for blob in _pdata_pdus_dimse(cstore_rs, cid=1):
        seg, tcpst = tcp_psh_exchange(sender="server", tcpst=tcpst, pdu=blob)
        pkts_out.extend(seg)

    pkts_out.extend(tcp_fin_teardown(tcpst))
    return pkts_out


def scenario_win7_ct_console() -> list[object]:
    w = WIN7_CONSOLE
    out: list[object] = [
        build_dhcp_discover_win7(w),
        build_dhcp_offer(
            client_mac=w["mac"],
            offered_ip=w["ip"],
            xid=WIN7_DHCP_XID_DISCOVER,
            hostname=w["name"],
        ),
        build_dhcp_request_win7(w, w["ip"]),
        build_dhcp_ack(
            client_mac=w["mac"],
            offered_ip=w["ip"],
            xid=WIN7_DHCP_XID_REQUEST,
            hostname=w["name"],
        ),
        build_llmnr_query(w, f"DC1.{DOMAIN_NAME.lower()}.local"),
        build_llmnr_query(w, "PACSARCH01"),
        build_llmnr_response(w["mac"], w["ip"], w["name"]),
        *build_arp_exchange(w, PACSARCH01),
        build_tcp_syn_windows(w, PACSARCH01, sport=49_301, dport=445),
        *build_arp_exchange(w, GATEWAY),
        *build_tls_client_hello(
            w, TLS_SENTINELONE, sport=49_302, sni="usea1-016.sentinelone.net"
        ),
        *build_tls_client_hello(
            w, TLS_MICROSOFT, sport=49_303, sni="events.data.microsoft.com"
        ),
        *build_smb2_negotiate_request(w, PACSARCH01, sport=49_304),
        *build_smb2_session_setup_ntlmssp(
            client=w,
            server=PACSARCH01,
            sport=49_306,
            client_hostname=w["name"],
            server_hostname=PACSARCH01["name"],
            domain=DOMAIN_NAME,
            username="ctop",
        ),
        *build_arp_exchange(w, ACMEWS02),
        build_tcp_syn_windows(w, ACMEWS02, sport=49_305, dport=7680),
    ]
    return out


def scenario_ccplatform_dhcp_llmnr() -> list[object]:
    out: list[object] = build_dora_for(
        CCPLATFORM,
        discover_xid=CCPLATFORM_DHCP_XID_DISCOVER,
        request_xid=CCPLATFORM_DHCP_XID_REQUEST,
        vendor_class_id="MSFT 5.0",
        param_req_list=WIN10_DHCP_PRL,
        ip_ttl=128,
    )
    out.append(build_llmnr_query(WIN7_CONSOLE, CCPLATFORM["name"]))
    out.append(
        build_llmnr_response(CCPLATFORM["mac"], CCPLATFORM["ip"], CCPLATFORM["name"])
    )
    return out


def scenario_acmews02() -> list[object]:
    out: list[object] = build_dora_for(
        ACMEWS02,
        discover_xid=ACMEWS02_DHCP_XID_DISCOVER,
        request_xid=ACMEWS02_DHCP_XID_REQUEST,
        vendor_class_id="MSFT 5.0",
        param_req_list=WIN10_DHCP_PRL,
        ip_ttl=128,
    )
    out.append(build_llmnr_query(WIN7_CONSOLE, ACMEWS02["name"]))
    out.append(
        build_llmnr_response(ACMEWS02["mac"], ACMEWS02["ip"], ACMEWS02["name"])
    )
    return out


def scenario_pacsarch01() -> list[object]:
    out: list[object] = build_dora_for(
        PACSARCH01,
        discover_xid=PACSARCH01_DHCP_XID_DISCOVER,
        request_xid=PACSARCH01_DHCP_XID_REQUEST,
        vendor_class_id="MSFT 5.0",
        param_req_list=WIN10_DHCP_PRL,
        ip_ttl=128,
    )
    out.append(
        build_llmnr_response(PACSARCH01["mac"], PACSARCH01["ip"], PACSARCH01["name"])
    )
    return out


# ── Assembly ──────────────────────────────────────────────────────────────────


def build_all_scenarios() -> list[tuple[str, list[object]]]:
    return [
        ("intellivue", scenario_intellivue_mx700()),
        ("brilliance_dhcp", scenario_brilliance_dhcp()),
        ("brilliance", scenario_brilliance_to_ccp()),
        ("win7", scenario_win7_ct_console()),
        ("ccplatform", scenario_ccplatform_dhcp_llmnr()),
        ("acmews02", scenario_acmews02()),
        ("pacsarch01", scenario_pacsarch01()),
    ]


def build_all_packets() -> list[object]:
    return [pkt for _, pkts in build_all_scenarios() for pkt in pkts]


def assemble_timestamps(
    scenarios: list[tuple[str, list[object]]],
    base_iso: str | None = None,
) -> None:
    if base_iso:
        dt = datetime.fromisoformat(base_iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        base = dt.timestamp()
    else:
        base = datetime(2026, 5, 14, 17, 0, tzinfo=UTC).timestamp()

    for tag, pkts in scenarios:
        offset = SCENARIO_OFFSETS_S.get(tag, 0.0)
        for idx, pkt in enumerate(pkts):
            pkt.time = base + offset + idx * INTRA_FLOW_STEP_S


def write_pcap_packets(path: Path, pkt_list: list[object]) -> Path:
    try:
        from scapy.all import wrpcap
    except ImportError as exc:
        raise SystemExit("pip install scapy") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), pkt_list, linktype=1)
    return path
