from __future__ import annotations

from tapirxl.parser._helpers import _base_record, _dns_layer, _layer_field_values


def handle(packet, oui_table: dict) -> dict | None:
    layer = _dns_layer(packet)
    # One announcement packet often carries several PTR answers (the
    # _services._dns-sd._udp.local enumeration plus one per service type);
    # take every occurrence, not just the first.
    ptr_names = [
        ptr
        for ptr in _layer_field_values(layer, "dns_ptr_domain_name")
        if ptr and any(x in ptr for x in ("._tcp.", "._udp."))
    ]
    if not ptr_names:
        return None
    rec = _base_record(packet, oui_table, "DNS_SD_PTR")
    if not rec:
        return None
    rec["raw_fields"] = {"ptr_domain_name": ptr_names[0], "ptr_domain_names": ptr_names}
    return rec
