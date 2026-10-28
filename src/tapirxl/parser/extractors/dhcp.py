from __future__ import annotations

import io
import re
from contextlib import redirect_stdout

from tapirxl.core.mac import normalize_mac
from tapirxl.core.oui import oui_lookup
from tapirxl.parser._helpers import _base_record, _safe
from tapirxl.parser.tables import DHCP_VENDOR_CLASS_MEDICAL, FINGERBANK_DHCP_55


def _dhcp_pretty_bundle(layer) -> str:
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            layer.pretty_print()
        s = buf.getvalue()
        if s.strip():
            return s
    except Exception:
        pass
    return str(layer or "")[:16000]


def _attribute_to_client(rec: dict, layer, oui_table: dict) -> bool:
    """File the record under the DHCP client (chaddr), not the frame's sender.

    A relay agent forwards the client's message with its own Ethernet and IP
    source but chaddr and options untouched (RFC 2131 §4.1), and a server's
    reply carries the client's chaddr too. Keying by eth.src would hand the
    client's hostname and fingerprint to the relay or server. The IP is the
    client's own ciaddr, never the relay's or server's address.

    Returns True when the packet is a client message (BOOTREQUEST), the only
    kind whose fingerprint fields (options 55, 60) describe the client.
    """
    chaddr = normalize_mac(_safe(layer, "hw_mac_addr", "") or "")
    if chaddr:
        rec["src_mac"] = chaddr
        rec["src_oui"] = oui_lookup(chaddr, oui_table)
        rec["src_ip"] = _safe(layer, "ip_client", "") or "0.0.0.0"
    return str(_safe(layer, "type", "1")) == "1"


def handle(packet, oui_table: dict) -> dict | None:
    dhcp = getattr(packet, "dhcp", None)
    bootp = getattr(packet, "bootp", None)
    if not dhcp and not bootp:
        return None
    rec = _base_record(packet, oui_table, "DHCP")
    if not rec:
        return None
    # bootp: tshark before 3.0 named the dissector bootp; current tshark has
    # only dhcp, which carries chaddr.
    from_client = _attribute_to_client(rec, dhcp, oui_table) if dhcp else True
    dump = _dhcp_pretty_bundle(dhcp) if dhcp else (str(bootp)[:8000] if bootp else "")
    prl_item_nums = sorted(
        {
            int(x)
            for x in re.findall(
                r"Parameter Request List Item:\s*\(([0-9]{1,3})\)",
                dump[:12000],
                re.I,
            )
            if x.isdigit() and int(x) <= 255
        }
    )
    if prl_item_nums:
        nums = prl_item_nums
    else:
        nums = sorted(
            {
                int(g)
                for g in re.findall(r"\(([0-9]{1,3})\)", dump[:12000])
                if g.isdigit() and int(g) <= 255
            }
        )
    if not from_client:  # a server reply's option list is not the client's PRL
        nums = []
    prl_key = ",".join(map(str, nums[:40]))

    vc = ""
    vc_m = re.search(r"Vendor class identifier:\s*([^\r\n]+)", dump, re.I) if from_client else None
    if vc_m:
        vc = vc_m.group(1).strip()
    if not vc and from_client:
        vc_m = re.search(r"Vendor class[^\n]+\n[^\n]*?:\s*([^\r\n]+)", dump, re.I | re.MULTILINE)
        if vc_m:
            vc = vc_m.group(1).strip()
    if not vc and from_client:
        vc_m = re.search(r"Option:\s*60[^\n]+\n[^\n]*?:\s*([^\r\n]+)", dump, re.I)
        if vc_m:
            vc = vc_m.group(1).strip()

    mh = ""
    mh_m = re.search(r"Host Name:\s*([^\r\n]+)", dump, re.I)
    if mh_m:
        mh = mh_m.group(1).strip()
    if not mh:
        mh_m = re.search(
            r"Hostname[^\n]+\n[^\n]*?:\s*([^\r\n]+)|Option:\s*12[^\n]+\n[^\n]*?:\s*([^\r\n]+)",
            dump,
            re.I,
        )
        if mh_m:
            mh = (mh_m.group(1) or mh_m.group(2) or "").strip()

    msg_type_m = re.search(
        r"DHCP[^:]*:\s*(Discover|Request|Offer|ACK|Nak|Decline|Release|Inform)",
        dump,
        re.I,
    )
    msg_type = msg_type_m.group(1).lower() if msg_type_m else ""

    fb_label = FINGERBANK_DHCP_55.get(prl_key, "") if prl_key else ""

    vc_match = ""
    if vc:
        for sub, lbl in DHCP_VENDOR_CLASS_MEDICAL:
            if sub.lower() in vc.lower():
                vc_match = lbl
                break

    rec["raw_fields"] = {
        "option12_hostname_hint": mh[:200],
        "option60_vendor_class": vc.strip()[:500],
        "option55_ordered_guess": nums,
        "option55_key_guess": prl_key,
        "fingerbank_dhcp_hit": fb_label,
        "vendor_medical_hint": vc_match,
        "dhcp_message_type": msg_type,
        "dhcp_text_excerpt": dump[:6000],
    }
    return rec


_MSG_TYPES = {
    "1": "discover",
    "2": "offer",
    "3": "request",
    "4": "decline",
    "5": "ack",
    "6": "nak",
    "7": "release",
    "8": "inform",
}


def sender(packet, oui_table: dict) -> dict | None:
    """A record for the frame's sender when it is not the DHCP client.

    Relays and servers stay visible as hosts that speak DHCP, at their own MAC
    and IP, while the client's options go only to the chaddr host (handle()).
    The record carries no option 12/55/60: those describe the client.
    """
    dhcp = getattr(packet, "dhcp", None)
    if not dhcp:
        return None
    chaddr = normalize_mac(_safe(dhcp, "hw_mac_addr", "") or "")
    rec = _base_record(packet, oui_table, "DHCP")
    if not rec or not chaddr or rec["src_mac"] == chaddr:
        return None
    rec["raw_fields"] = {
        "option12_hostname_hint": "",
        "option60_vendor_class": "",
        "option55_ordered_guess": [],
        "option55_key_guess": "",
        "fingerbank_dhcp_hit": "",
        "vendor_medical_hint": "",
        "dhcp_message_type": _MSG_TYPES.get(str(_safe(dhcp, "option_dhcp", "")), ""),
        "dhcp_text_excerpt": "",
    }
    return rec
