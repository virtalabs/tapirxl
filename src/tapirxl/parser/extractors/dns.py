from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _safe


def handle(packet, oui_table: dict) -> dict | None:
    if not hasattr(packet, "dns"):
        return None
    if hasattr(packet, "udp") and str(_safe(packet.udp, "dstport", "")) == "5353":
        return None
    qtype = _safe(packet.dns, "qry_type", "")
    qname = _safe(packet.dns, "qry_name", "")
    resp_name = _safe(packet.dns, "resp_name", "")
    mdns_specific = getattr(packet.dns, "txt", None) or getattr(packet.dns, "a", None)
    ptr = _safe(packet.dns, "ptr_domain_name")
    if not qname and not ptr:
        return None
    rec = _base_record(packet, oui_table, "DNS_LOOKUP")
    if not rec:
        return None
    vendor_hits = []
    for dom in filter(None, [qname, ptr, resp_name]):
        ds = str(dom).lower()
        if any(x in ds for x in ("siemens", "philips", "ge-", "oraclehealth", "epic")):
            vendor_hits.append(dom)
    rec["raw_fields"] = {
        "qtype": qtype,
        "qname": qname or ptr or resp_name,
        "vendor_domain_hits": vendor_hits,
        "_mdns_layer_present": mdns_specific is not None,
    }
    return rec
