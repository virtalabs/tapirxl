"""Single-pass pyshark sweep → list of HostEnvelope dicts."""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from pathlib import Path

from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import load_oui_table
from tapirxl.parser._helpers import _safe
from tapirxl.parser.deterministic import postprocess_pipeline_labels
from tapirxl.parser.envelope_builder import (
    finalize_envelope_from_records,
    make_empty_envelope,
    merge_record_into_envelope,
)
from tapirxl.parser.extractors import (
    arp,
    capsule_mdip,
    dhcp,
    dicom,
    dns,
    dns_sd,
    expert,
    hl7,
    kerberos,
    llmnr,
    mdns,
    smb2,
    snmp,
    ssdp,
    ssh,
    tcp_syn,
    tls_sni,
    ws_discovery,
)
from tapirxl.parser.tables import DISPLAY_FILTER
from tapirxl.parser.triage import contradiction_scan, route_host


def _push(emits: list[dict], record: dict | None) -> None:
    if record:
        emits.append(record)


def extract_packets(pcap_path: str, oui_table: dict) -> list[dict]:
    import pyshark

    records: list[dict] = []
    pkt_loop = asyncio.new_event_loop()
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=DISPLAY_FILTER,
        keep_packets=False,
        eventloop=pkt_loop,
    )
    pkt_count = 0
    try:
        for packet in cap:
            pkt_count += 1
            if pkt_count % 5000 == 0:
                print(
                    f"\r  {pkt_count} packets scanned, {len(records)} records...",
                    end="",
                    file=sys.stderr,
                )
            try:
                udp_dport = _safe(packet.udp, "dstport", "") if hasattr(packet, "udp") else ""
                udp_sport = _safe(packet.udp, "srcport", "") if hasattr(packet, "udp") else ""

                emits: list[dict] = []

                if hasattr(packet, "dhcp") or hasattr(packet, "bootp"):
                    _push(emits, dhcp.handle(packet, oui_table))

                if udp_dport == "1900" or udp_sport == "1900":
                    _push(emits, ssdp.handle(packet, oui_table))

                if udp_dport == "3702":
                    _push(emits, ws_discovery.handle(packet, oui_table))

                elif udp_dport == "5353":
                    mdns_before = len(emits)
                    _push(emits, mdns.handle_txt(packet, oui_table))
                    _push(emits, mdns.handle_a(packet, oui_table))
                    _push(emits, dns_sd.handle(packet, oui_table))
                    if len(emits) == mdns_before:
                        _push(emits, dns.handle(packet, oui_table))

                elif udp_dport == "5355":
                    _push(emits, llmnr.handle(packet, oui_table))

                elif udp_dport == "5090" or udp_sport == "5090":
                    _push(emits, capsule_mdip.handle(packet, oui_table))

                _push(emits, arp.handle(packet, oui_table))

                if hasattr(packet, "tcp"):
                    dstp = str(_safe(packet.tcp, "dstport") or "")
                    sportp = str(_safe(packet.tcp, "srcport") or "")
                    _push(emits, tcp_syn.handle(packet, oui_table))
                    if dstp in ("104", "2104", "2762") or sportp in ("104", "2104", "2762"):
                        _push(emits, dicom.handle(packet, oui_table))
                    _push(emits, ssh.handle(packet, oui_table))
                    _push(emits, hl7.handle(packet, oui_table))

                _push(emits, tls_sni.handle(packet, oui_table))
                _push(emits, smb2.handle(packet, oui_table))
                _push(emits, smb2.handle_ntlmssp(packet, oui_table))
                _push(emits, kerberos.handle(packet, oui_table))

                if hasattr(packet, "dns") and udp_dport not in ("5353", "5355"):
                    _push(emits, dns.handle(packet, oui_table))

                _push(emits, snmp.handle(packet, oui_table))

                emits = [e for e in emits if e]
                _push(emits, expert.handle(packet, oui_table))
                emits = [e for e in emits if e]

                for rec in emits:
                    records.append(rec)
            except Exception:
                continue
    finally:
        cap.close()
        pkt_loop.close()
    print(
        f"\r  {pkt_count} packets scanned, {len(records)} records extracted.",
        file=sys.stderr,
    )
    return records


def build_signal_register(records: list[dict], oui_table: dict) -> list[dict]:
    by_mac: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        mac = normalize_mac(rec.get("src_mac") or "")
        if not mac:
            continue
        by_mac[mac].append(rec)

    rows: list[dict] = []
    for mac, rec_list in sorted(by_mac.items(), key=lambda item: item[0]):
        env = make_empty_envelope(mac, oui_table)
        for rec in sorted(rec_list, key=lambda x: float(x.get("timestamp", 0))):
            merge_record_into_envelope(env, rec)
        finalize_envelope_from_records(env)
        contradiction_scan(env)
        postprocess_pipeline_labels(env)
        route_host(env)
        rows.append(env)
    return rows


def run(pcap_path: str) -> list[dict]:
    """Parse a PCAP and return the full signal register."""
    oui_table = load_oui_table(Path.cwd() / "static" / "ieee_oui.txt")
    records = extract_packets(pcap_path, oui_table)
    return build_signal_register(records, oui_table)
