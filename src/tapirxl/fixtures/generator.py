"""Manifest-driven PCAP packet generator.

Iterates a :class:`~tapirxl.fixtures.manifest.SignalManifest`, dispatches each
asset's solo signals and multi-host flows to the appropriate protocol emitter,
merges the resulting packets by timestamp, and returns a flat list ready for
:func:`write_pcap_packets`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from tapirxl.fixtures.manifest import SignalManifest
from tapirxl.fixtures.protocols import arp, dhcp, dicom, llmnr, smb2, tcp_syn, tls, wsdiscovery

# ── Dispatch tables ───────────────────────────────────────────────────────────

SOLO_HANDLERS: dict[str, Any] = {
    "dhcp": dhcp.emit_solo,
    "wsdiscovery": wsdiscovery.emit_solo,
    "llmnr_response": llmnr.emit_solo_response,
    # tcp_syn solo (per-asset) is not currently used in the shipped manifest;
    # solo tcp_syn sub-tables are validated by the manifest model but dispatched
    # only via flow entries (FlowTcpSyn) to keep the L2 target resolvable.
}

FLOW_HANDLERS: dict[str, Any] = {
    "arp_exchange": arp.emit_flow,
    "dicom_associate_and_cstore": dicom.emit_flow,
    "smb2_negotiate": smb2.emit_negotiate_flow,
    "smb2_session_setup_ntlmssp": smb2.emit_ntlmssp_flow,
    "tls_client_hello": tls.emit_flow,
    "llmnr_query": llmnr.emit_query_flow,
    "tcp_syn": tcp_syn.emit_flow,
}


# ── Generator ─────────────────────────────────────────────────────────────────


def generate_packets(manifest: SignalManifest) -> list[object]:
    """Return a flat list of scapy packets in chronological PCAP order.

    Packets share the same ``emit_at_s`` bucket are ordered by insertion
    (asset declaration order, then flow declaration order).  Absolute
    timestamps are applied from ``scenario.pcap_base_timestamp`` using
    ``intra_flow_step_s`` as the per-packet jitter increment within a bucket.
    """
    timed: list[tuple[float, object]] = []

    for _slug, asset in manifest.assets.items():
        for proto in asset.emits:
            handler = SOLO_HANDLERS.get(proto)
            if handler is None:
                continue
            for emit_at_s, pkt in handler(asset, manifest):
                timed.append((emit_at_s, pkt))

    for flow in manifest.flows:
        handler = FLOW_HANDLERS.get(flow.type)
        if handler is None:
            continue
        for emit_at_s, pkt in handler(flow, manifest):
            timed.append((emit_at_s, pkt))

    timed.sort(key=lambda x: x[0])
    _apply_timestamps(timed, manifest)
    return [pkt for _, pkt in timed]


def _apply_timestamps(
    timed: list[tuple[float, object]],
    manifest: SignalManifest,
) -> None:
    """Stamp each packet's time field in-place.

    Within a group of packets sharing the same ``emit_at_s``, each successive
    packet is advanced by ``intra_flow_step_s`` to preserve ordering.
    """
    base: datetime = manifest.scenario.pcap_base_timestamp
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)

    step = manifest.scenario.intra_flow_step_s
    prev_offset = -1.0
    intra_idx = 0

    for i, (emit_at_s, pkt) in enumerate(timed):
        if emit_at_s != prev_offset:
            intra_idx = 0
            prev_offset = emit_at_s
        else:
            intra_idx += 1

        ts = base + timedelta(seconds=emit_at_s + step * intra_idx)
        _stamp(pkt, ts)
        timed[i] = (emit_at_s, pkt)


def _stamp(pkt: object, ts: datetime) -> None:
    """Set the scapy packet's ``time`` attribute to a UNIX timestamp."""
    try:
        pkt.time = ts.timestamp()  # type: ignore[union-attr]
    except AttributeError:
        pass


# ── PCAP writer ───────────────────────────────────────────────────────────────


def write_pcap_packets(output_path: Path, packets: list[object]) -> None:
    """Write *packets* to a PCAP file at *output_path*."""
    try:
        from scapy.utils import wrpcap
    except ImportError as exc:
        raise SystemExit("Install scapy: pip install scapy") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
