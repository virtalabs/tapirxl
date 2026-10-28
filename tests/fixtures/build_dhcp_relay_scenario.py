"""Build tests/fixtures/dhcp_relay_scenario.pcap: DHCP through a relay agent.

A router-on-a-stick relays DHCP for two client VLANs to one server, as hospital
networks do. The capture point is a core SPAN that sees both the client's
broadcast and the relay's unicast copy, so every client message appears twice:

  1. client  -> broadcast   eth.src = client MAC, ip 0.0.0.0 -> 255.255.255.255
  2. relay   -> server      eth.src = ROUTER MAC, ip relay -> server, giaddr set
  3. server  -> relay       eth.src = server MAC, ip server -> giaddr
  4. relay   -> client      eth.src = ROUTER MAC, ip giaddr -> yiaddr

Per RFC 2131 §4.1 the relay sets giaddr and forwards chaddr and the client's
options (including option 12) untouched, and the server echoes option 12 in
its replies. In frames 2 and 4 the client's identity is therefore in the DHCP
header (chaddr) while the Ethernet and IP headers carry the router's.

Shape reproduced from a capture on the Brookhaven test range (2026-10-28),
where TapirXL attributed relayed client hostnames to the core router. All
identities here are synthetic.

    uv run python tests/fixtures/build_dhcp_relay_scenario.py   # rewrites the pcap
"""

from __future__ import annotations

from pathlib import Path

PCAP = Path(__file__).with_name("dhcp_relay_scenario.pcap")
BASE_TS = 1793194200.0  # 2026-10-28T13:30:00Z, fixed so the pcap is byte-stable

ROUTER_MAC = "00:1c:73:0a:00:01"  # one MAC on every VLAN interface (router-on-a-stick)
RELAY_UPSTREAM_IP = "10.50.20.1"  # relay's address on the server VLAN
SERVER_MAC = "00:50:56:0a:00:12"
SERVER_IP = "10.50.20.12"

# (client MAC, hostname, VLAN gateway = giaddr, reserved address)
CLIENTS = [
    ("00:09:fb:30:00:07", "ICU-MON-07", "10.50.30.1", "10.50.30.107"),
    ("00:0e:2f:40:00:02", "LAB-ANALYZER-02", "10.50.40.1", "10.50.40.102"),
]
PRL = [1, 3, 6, 12, 15, 28, 42]


def _hw(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "")) + bytes(10)


def _client_msg(mac: str, hostname: str, msg: str, xid: int, requested: str | None):
    from scapy.layers.dhcp import BOOTP, DHCP

    opts: list = [("message-type", msg), ("hostname", hostname)]
    if requested:
        opts.append(("requested_addr", requested))
    opts += [("param_req_list", PRL), "end"]
    return BOOTP(op=1, xid=xid, flags=0x8000, chaddr=_hw(mac)), DHCP(options=opts)


def _server_msg(mac: str, hostname: str, msg: str, xid: int, yiaddr: str, giaddr: str):
    from scapy.layers.dhcp import BOOTP, DHCP

    opts = [
        ("message-type", msg),
        ("server_id", SERVER_IP),
        ("lease_time", 3600),
        ("subnet_mask", "255.255.255.0"),
        ("router", giaddr),
        ("hostname", hostname),  # servers echo option 12 (Kea, ISC, Windows)
        "end",
    ]
    return BOOTP(op=2, xid=xid, hops=1, yiaddr=yiaddr, giaddr=giaddr, chaddr=_hw(mac)), DHCP(
        options=opts
    )


def build() -> list:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    pkts = []
    for n, (mac, host, giaddr, ip) in enumerate(CLIENTS):
        for step, (cmsg, smsg) in enumerate((("discover", "offer"), ("request", "ack"))):
            xid = 0x5A000000 + n * 16 + step
            requested = ip if cmsg == "request" else None
            bootp, dhcp = _client_msg(mac, host, cmsg, xid, requested)
            # 1. client broadcast on its VLAN
            pkts.append(
                Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255", ttl=64)
                / UDP(sport=68, dport=67)
                / bootp
                / dhcp
            )
            # 2. relay -> server: same options and chaddr, giaddr set, hops+1
            relayed = bootp.copy()
            relayed.giaddr, relayed.hops = giaddr, 1
            pkts.append(
                Ether(src=ROUTER_MAC, dst=SERVER_MAC)
                / IP(src=RELAY_UPSTREAM_IP, dst=SERVER_IP, ttl=64)
                / UDP(sport=67, dport=67)
                / relayed
                / dhcp.copy()
            )
            sbootp, sdhcp = _server_msg(mac, host, smsg, xid, ip, giaddr)
            # 3. server -> relay
            pkts.append(
                Ether(src=SERVER_MAC, dst=ROUTER_MAC)
                / IP(src=SERVER_IP, dst=giaddr, ttl=64)
                / UDP(sport=67, dport=67)
                / sbootp
                / sdhcp
            )
            # 4. relay -> client
            pkts.append(
                Ether(src=ROUTER_MAC, dst=mac)
                / IP(src=giaddr, dst=ip, ttl=64)
                / UDP(sport=67, dport=68)
                / sbootp.copy()
                / sdhcp.copy()
            )
    for i, p in enumerate(pkts):
        p.time = BASE_TS + i * 0.01
    return pkts


if __name__ == "__main__":
    from scapy.utils import wrpcap

    pkts = build()
    wrpcap(str(PCAP), pkts)
    print(f"wrote {PCAP} ({len(pkts)} packets)")
