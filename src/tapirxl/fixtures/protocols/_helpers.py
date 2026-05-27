"""Low-level packet construction primitives used by protocol emitters.

All scapy imports are deferred inside functions so importing this module does
not require scapy to be installed.  These are protocol-mandated byte layouts
and TCP state-machine helpers — zero scenario constants.
"""

from __future__ import annotations

import codecs
import struct
from dataclasses import dataclass
from typing import Literal

# ── TCP flag constants (pre-resolved per REQ-PRE-002) ─────────────────────────

SYN = 0x002
SYN_ACK = SYN | 0x010  # pre-resolved: 0x012
ACK = 0x010
PSH_ACK = 0x008 | ACK  # pre-resolved: 0x018
FIN_ACK = 0x001 | ACK  # pre-resolved: 0x011

# Windows 7 SP1 TCP SYN option set (protocol-mandated layout, not scenario data)
_WIN7_SYN_OPTS: list = [
    ("MSS", 1460),
    ("NOP", None),
    ("WScale", 8),
    ("SAckOK", b""),
    ("EOL", None),
]

# ── NTLMSSP protocol constants ────────────────────────────────────────────────

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


# ── MAC / byte helpers ────────────────────────────────────────────────────────


def _mac_to_bootp_hw(mac_colon: str) -> bytes:
    h = codecs.decode(mac_colon.replace(":", ""), "hex")
    return (h + b"\x00" * 10)[:16]


def _nbss_session_message_payload(smb_payload: bytes) -> bytes:
    length = len(smb_payload)
    return b"\x00" + struct.pack("!I", length)[1:] + smb_payload


def _sec_buffer(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def _av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


# ── Low-level Ethernet / IP / UDP / TCP frame builders ───────────────────────


def _eth_ip_udp(
    *,
    ether_src: str,
    ether_dst: str,
    ip_src: str,
    ip_dst: str,
    udp_sport: int,
    udp_dport: int,
    payload: bytes,
    ip_ttl: int | None = None,
) -> object:
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether
    except ImportError as exc:
        raise SystemExit("Install scapy: pip install scapy") from exc

    ttl = ip_ttl if ip_ttl is not None else (1 if ip_dst.startswith("239.") else 64)
    return (
        Ether(src=ether_src, dst=ether_dst)
        / IP(src=ip_src, dst=ip_dst, ttl=ttl)
        / UDP(sport=udp_sport, dport=udp_dport)
        / payload
    )


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


# ── TCP state machine ─────────────────────────────────────────────────────────


def tcp_three_way_hs(st: TcpState, sport: int, dport: int) -> tuple[list[object], TcpState]:
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
        ether_src, ether_dst = tcpst.client_mac, tcpst.server_mac
        ip_src, ip_dst = tcpst.client_ip, tcpst.server_ip
        sport, dport = tcpst.client_port, tcpst.server_port
        seq_here, ack_peer = tcpst.cli_seq, tcpst.srv_seq
        next_cli, next_srv = tcpst.cli_seq + len(pdu), tcpst.srv_seq
        sender_ttl = tcpst.client_ttl
    else:
        ether_src, ether_dst = tcpst.server_mac, tcpst.client_mac
        ip_src, ip_dst = tcpst.server_ip, tcpst.client_ip
        sport, dport = tcpst.server_port, tcpst.client_port
        seq_here, ack_peer = tcpst.srv_seq, tcpst.cli_seq
        next_srv, next_cli = tcpst.srv_seq + len(pdu), tcpst.cli_seq
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
        pkts.append(
            _tcp_eth(
                ether_src=tcpst.server_mac,
                ether_dst=tcpst.client_mac,
                ip_src=tcpst.server_ip,
                ip_dst=tcpst.client_ip,
                sport=tcpst.server_port,
                dport=tcpst.client_port,
                flags=ACK,
                seq=tcpst.srv_seq,
                ack_num=next_cli,
                ip_ttl=tcpst.server_ttl,
            )
        )
        new_st = TcpState(
            cli_seq=next_cli,
            srv_seq=tcpst.srv_seq,
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
        pkts.append(
            _tcp_eth(
                ether_src=tcpst.client_mac,
                ether_dst=tcpst.server_mac,
                ip_src=tcpst.client_ip,
                ip_dst=tcpst.server_ip,
                sport=tcpst.client_port,
                dport=tcpst.server_port,
                flags=ACK,
                seq=tcpst.cli_seq,
                ack_num=next_srv,
                ip_ttl=tcpst.client_ttl,
            )
        )
        new_st = TcpState(
            cli_seq=tcpst.cli_seq,
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


# ── NTLMSSP byte builders ─────────────────────────────────────────────────────


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
    out += bytes(8)  # version placeholder (filled by caller if needed)
    out += domain_b + ws_b
    return out


def build_ntlmssp_negotiate_versioned(domain: str, workstation: str, version: bytes) -> bytes:
    """NTLMSSP NEGOTIATE with a specific version blob."""
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
    out += version[:8].ljust(8, b"\x00")
    out += domain_b + ws_b
    return out


def build_ntlmssp_challenge(
    target_name: str,
    domain: str,
    server_hostname: str,
    server_challenge: bytes,
) -> bytes:
    target_w = _utf16le(target_name)
    av_dom_w = _utf16le(domain)
    av_srv_w = _utf16le(server_hostname)
    av_dnsdom_w = _utf16le(f"{domain.lower()}.local")
    av_dnssrv_w = _utf16le(f"{server_hostname.lower()}.{domain.lower()}.local")
    av_pairs = (
        _av_pair(0x0002, av_dom_w)
        + _av_pair(0x0001, av_srv_w)
        + _av_pair(0x0004, av_dnsdom_w)
        + _av_pair(0x0003, av_dnssrv_w)
        + _av_pair(0x0007, b"\x00" * 8)
        + _av_pair(0x0000, b"")
    )
    flags = NTLM_NEG_FLAGS_BASE | 0x00100000
    reserved = b"\x00" * 8
    header_len = 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8
    target_off = header_len
    av_off = target_off + len(target_w)
    out = NTLMSSP_SIGNATURE
    out += struct.pack("<I", NTLM_TYPE2_CHALLENGE)
    out += _sec_buffer(len(target_w), target_off)
    out += struct.pack("<I", flags)
    out += server_challenge[:8]
    out += reserved
    out += _sec_buffer(len(av_pairs), av_off)
    out += bytes(8)  # version placeholder
    out += target_w + av_pairs
    return out


def build_ntlmssp_authenticate(*, domain: str, username: str, workstation: str) -> bytes:
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
    out += bytes(8)  # version placeholder
    out += lm_resp + nt_resp + dom_w + user_w + ws_w + sess_key
    return out


# ── SMB2 frame builders ───────────────────────────────────────────────────────


def smb2_sync_header(command: int = 0, message_id: int = 1, *, response: bool = False) -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<H", hdr, 4, 64)
    struct.pack_into("<H", hdr, 6, 0)
    struct.pack_into("<I", hdr, 8, 0)
    struct.pack_into("<H", hdr, 12, command)
    struct.pack_into("<H", hdr, 14, 126)
    flags = 0x00000001 if response else 0
    struct.pack_into("<I", hdr, 16, flags)
    struct.pack_into("<I", hdr, 20, 0)
    struct.pack_into("<Q", hdr, 24, message_id)
    struct.pack_into("<I", hdr, 32, 0)
    struct.pack_into("<I", hdr, 36, 0)
    struct.pack_into("<Q", hdr, 40, 0)
    return bytes(hdr)


def smb2_negotiate_request_body(client_guid: bytes, dialects: list[int]) -> bytes:
    body = struct.pack("<HHHH", 36, len(dialects), 1, 0)
    body += struct.pack("<I", 0)
    body += client_guid[:16].ljust(16, b"\x00")
    body += struct.pack("<Q", 0)
    for d in dialects:
        body += struct.pack("<H", d)
    return body


def smb2_session_setup_request_body(security_blob: bytes) -> bytes:
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


def smb2_session_setup_response_body(security_blob: bytes) -> bytes:
    structure_size = 9
    session_flags = 0
    sec_offset = 0x48
    sec_length = len(security_blob)
    body = struct.pack("<HHHH", structure_size, session_flags, sec_offset, sec_length)
    return body + security_blob


# ── TLS byte builders ─────────────────────────────────────────────────────────


def tls_extensions_client_hello(sni: str) -> bytes:
    sni_b = sni.encode("ascii")
    snilist = (
        struct.pack("!H", len(sni_b) + 3) + bytes([0x00]) + struct.pack("!H", len(sni_b)) + sni_b
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


def tls_client_hello_plaintext(sni: str) -> bytes:
    rng = bytes.fromhex("deadbeef" * 8)
    _su_win7_sp1 = (
        0xC027,
        0xC028,
        0xC02F,
        0xC030,
        0xC013,
        0xC014,
        0xC009,
        0xC00A,
        0x009C,
        0x009D,
        0x002F,
        0x003C,
        0x009E,
        0x009F,
        0xCC14,
        0xCC13,
        0xCC15,
        0x0013,
        0x0032,
        0x0035,
        0x005C,
    )
    ciphersuites = b"".join(struct.pack("!H", x) for x in _su_win7_sp1)
    comp = b"\x01\x00"
    exts = tls_extensions_client_hello(sni)
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
