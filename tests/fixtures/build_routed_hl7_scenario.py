"""Build tests/fixtures/routed_hl7_scenario.pcap: HL7 routed between VLANs.

A lab analyzer on VLAN 40 sends an HL7 ORU to an interface engine on VLAN 20
through a router-on-a-stick. The SPAN sees both legs of every routed packet:

  1. sender -> router   eth.src = SENDER MAC, ip sender -> receiver, ttl 64
  2. router -> receiver eth.src = ROUTER MAC, ip sender -> receiver, ttl 63

so leg 2 carries the router's MAC with the sender's IP. ARP on each VLAN
binds every IP to its owner, and the router makes one TCP connection of its
own (a SYN from its VLAN 40 address), which must stay with the router.

Shape reproduced from the Brookhaven test range (2026-10-28), where TapirXL
credited routed HL7 to the core router. All identities here are synthetic.

    uv run python tests/fixtures/build_routed_hl7_scenario.py   # rewrites the pcap
"""

from __future__ import annotations

from pathlib import Path

PCAP = Path(__file__).with_name("routed_hl7_scenario.pcap")
BASE_TS = 1793280600.0  # 2026-10-29T13:30:00Z, fixed so the pcap is byte-stable

ROUTER_MAC = "00:1c:73:0a:00:01"  # one MAC on every VLAN interface
ROUTER_IP = "10.50.40.1"
LAB_MAC, LAB_IP = "00:0e:2f:40:00:02", "10.50.40.102"
ENGINE_MAC, ENGINE_IP = "00:50:56:0a:00:20", "10.50.20.20"

ORU = "MSH|^~\\&|COBAS|LAB|MIRTH|HOSP|20261029133000||ORU^R01|MSG0001|P|2.5\rPID|1||SYN0001\r"
ACK = "MSH|^~\\&|MIRTH|HOSP|COBAS|LAB|20261029133001||ACK^R01|ACK0001|P|2.5\rMSA|AA|MSG0001\r"


def _mllp(msg: str) -> bytes:
    return b"\x0b" + msg.encode() + b"\x1c\x0d"


def build() -> list:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP, Ether

    def arp(mac: str, ip: str, target: str):
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst=target)

    def routed(src_mac: str, src: str, dst_mac: str, dst: str, sport: int, dport: int, msg: str):
        tcp = TCP(sport=sport, dport=dport, flags="PA", seq=1000, ack=1)
        return [
            Ether(src=src_mac, dst=ROUTER_MAC) / IP(src=src, dst=dst, ttl=64) / tcp / _mllp(msg),
            Ether(src=ROUTER_MAC, dst=dst_mac) / IP(src=src, dst=dst, ttl=63) / tcp / _mllp(msg),
        ]

    pkts = [
        arp(LAB_MAC, LAB_IP, ROUTER_IP),
        arp(ENGINE_MAC, ENGINE_IP, "10.50.20.1"),
        arp(ROUTER_MAC, ROUTER_IP, LAB_IP),
        *routed(LAB_MAC, LAB_IP, ENGINE_MAC, ENGINE_IP, 40000, 2575, ORU),
        *routed(ENGINE_MAC, ENGINE_IP, LAB_MAC, LAB_IP, 2575, 40000, ACK),
        Ether(src=ROUTER_MAC, dst=LAB_MAC)
        / IP(src=ROUTER_IP, dst=LAB_IP, ttl=64)
        / TCP(sport=51000, dport=22, flags="S", options=[("MSS", 1460), ("WScale", 7)]),
    ]
    for i, p in enumerate(pkts):
        p.time = BASE_TS + i * 0.01
    return pkts


if __name__ == "__main__":
    from scapy.utils import wrpcap

    pkts = build()
    wrpcap(str(PCAP), pkts)
    print(f"wrote {PCAP} ({len(pkts)} packets)")
