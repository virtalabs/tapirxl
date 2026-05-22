"""SMB2 Negotiate and SMB2 Session-Setup NTLMSSP emitters."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from tapirxl.fixtures.protocols._helpers import (
    TcpState,
    _nbss_session_message_payload,
    build_ntlmssp_authenticate,
    build_ntlmssp_challenge,
    build_ntlmssp_negotiate_versioned,
    smb2_negotiate_request_body,
    smb2_session_setup_request_body,
    smb2_session_setup_response_body,
    smb2_sync_header,
    tcp_psh_exchange,
    tcp_three_way_hs,
)

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import (
        FlowSmb2Negotiate,
        FlowSmb2NtlmsspSetup,
        SignalManifest,
    )

_SMB2_PORT = 445


def emit_negotiate_flow(
    flow: FlowSmb2Negotiate, manifest: SignalManifest
) -> Iterable[tuple[float, object]]:
    client = manifest.assets[flow.client]
    server = manifest.assets[flow.server]
    sport = flow.client_port

    smb = smb2_sync_header(0, 1) + smb2_negotiate_request_body(flow.client_guid_hex, flow.dialects)
    pdu = _nbss_session_message_payload(smb)
    init = TcpState(
        cli_seq=0x7E330000 + (sport & 0xFFFF),
        srv_seq=0x7E440000 + (sport & 0xFFFF),
        client_mac=client.mac,
        server_mac=server.mac,
        client_ip=client.ip,
        server_ip=server.ip,
        client_port=sport,
        server_port=_SMB2_PORT,
    )
    hs, tcpst = tcp_three_way_hs(init, sport, _SMB2_PORT)
    seg, _ = tcp_psh_exchange(sender="client", tcpst=tcpst, pdu=pdu)
    for pkt in [*hs, *seg]:
        yield (flow.emit_at_s, pkt)


def emit_ntlmssp_flow(
    flow: FlowSmb2NtlmsspSetup, manifest: SignalManifest
) -> Iterable[tuple[float, object]]:
    client = manifest.assets[flow.client]
    server = manifest.assets[flow.server]
    sport = flow.client_port
    client_hostname = client.hostname or client.mac
    server_hostname = server.hostname or server.mac

    init = TcpState(
        cli_seq=0x7E550000 + (sport & 0xFFFF),
        srv_seq=0x7E660000 + (sport & 0xFFFF),
        client_mac=client.mac,
        server_mac=server.mac,
        client_ip=client.ip,
        server_ip=server.ip,
        client_port=sport,
        server_port=_SMB2_PORT,
    )
    pkts: list[object] = []
    hs, tcpst = tcp_three_way_hs(init, sport, _SMB2_PORT)
    pkts.extend(hs)

    # Leg 1: NEGOTIATE (client → server)
    neg = build_ntlmssp_negotiate_versioned(flow.domain, client_hostname, flow.version_hex)
    smb_req1 = smb2_sync_header(command=1, message_id=2) + smb2_session_setup_request_body(neg)
    seg, tcpst = tcp_psh_exchange(
        sender="client", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_req1)
    )
    pkts.extend(seg)

    # Leg 2: CHALLENGE (server → client)
    chal = build_ntlmssp_challenge(
        target_name=flow.domain,
        domain=flow.domain,
        server_hostname=server_hostname,
        server_challenge=flow.server_challenge_hex,
    )
    smb_resp1 = smb2_sync_header(command=1, message_id=2) + smb2_session_setup_response_body(chal)
    seg, tcpst = tcp_psh_exchange(
        sender="server", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_resp1)
    )
    pkts.extend(seg)

    # Leg 3: AUTHENTICATE (client → server)
    auth = build_ntlmssp_authenticate(
        domain=flow.domain, username=flow.username, workstation=client_hostname
    )
    smb_req2 = smb2_sync_header(command=1, message_id=3) + smb2_session_setup_request_body(auth)
    seg, tcpst = tcp_psh_exchange(
        sender="client", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_req2)
    )
    pkts.extend(seg)

    # Final ACK (server → client)
    smb_resp2 = smb2_sync_header(command=1, message_id=3) + smb2_session_setup_response_body(b"")
    seg, _ = tcp_psh_exchange(
        sender="server", tcpst=tcpst, pdu=_nbss_session_message_payload(smb_resp2)
    )
    pkts.extend(seg)

    for pkt in pkts:
        yield (flow.emit_at_s, pkt)
