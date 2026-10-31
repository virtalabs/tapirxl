from __future__ import annotations

from tapirxl.parser._helpers import (
    _base_record,
    _dns_layer,
    _layer_field_values,
    _layer_fields,
)


def _field_pos(field) -> int | None:
    try:
        pos = getattr(field, "pos", None)
        return int(pos) if pos is not None else None
    except TypeError, ValueError:
        return None


def _a_record_owner(layer) -> str | None:
    """Owner (response) name of the first A record in an mDNS layer.

    pyshark flattens the DNS record tree, so the A record's owner is the
    dns_resp_name occurrence closest before it in the frame (fall back to the
    last occurrence when byte positions are unavailable). The flat
    dns_resp_name attribute is the *first* answer's name (e.g. the
    _services._dns-sd._udp.local enumeration PTR), not the A record's owner.
    """
    names: list[tuple[int, str]] = []
    for field in _layer_fields(layer, "dns_resp_name"):
        try:
            val = field.get_default_value()
        except Exception:
            val = None
        if val:
            names.append((_field_pos(field), str(val)))
    for field in _layer_fields(layer, "dns_a"):
        pos = _field_pos(field)
        prior = [v for p, v in names if p is not None and pos is not None and p < pos]
        if prior:
            return prior[-1]
        if names:
            return names[-1][1]
    return None


def handle_txt(packet, oui_table: dict) -> dict | None:
    layer = _dns_layer(packet)
    txt_values = _layer_field_values(layer, "dns_txt")
    if not txt_values:
        return None
    rec = _base_record(packet, oui_table, "MDNS_TXT")
    if not rec:
        return None
    # Each dns_txt occurrence is one TXT string. Do not split on ';': a valid
    # value can contain a semicolon, and no capture format is known to use it
    # as a reliable delimiter between strings.
    txt_entries: list[str] = [
        str(txt_raw).strip() for txt_raw in txt_values if str(txt_raw).strip()
    ]
    txt_parsed: dict[str, str] = {}
    for entry in txt_entries:
        if "=" in entry:
            k, _, v = entry.partition("=")
            txt_parsed[k.strip()] = v.strip()
    resp_names = _layer_field_values(layer, "dns_resp_name")
    rec["raw_fields"] = {
        "resp_name": resp_names[0] if resp_names else None,
        "mdns_txt_raw": txt_entries,
        "mdns_txt_parsed": txt_parsed,
    }
    return rec


def handle_a(packet, oui_table: dict) -> dict | None:
    layer = _dns_layer(packet)
    a_values = _layer_field_values(layer, "dns_a")
    if not a_values:
        return None
    rec = _base_record(packet, oui_table, "MDNS_A")
    if not rec:
        return None
    rec["raw_fields"] = {
        "mdns_hostname": _a_record_owner(layer),
        "resolved_ip": a_values[0],
    }
    return rec
