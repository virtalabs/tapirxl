from __future__ import annotations

import io
import re
from contextlib import redirect_stdout

from tapirxl.parser._helpers import _base_record
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


def handle(packet, oui_table: dict) -> dict | None:
    dhcp = getattr(packet, "dhcp", None)
    bootp = getattr(packet, "bootp", None)
    if not dhcp and not bootp:
        return None
    rec = _base_record(packet, oui_table, "DHCP")
    if not rec:
        return None
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
    prl_key = ",".join(map(str, nums[:40]))

    vc = ""
    vc_m = re.search(r"Vendor class identifier:\s*([^\r\n]+)", dump, re.I)
    if vc_m:
        vc = vc_m.group(1).strip()
    if not vc:
        vc_m = re.search(
            r"Vendor class[^\n]+\n[^\n]*?:\s*([^\r\n]+)", dump, re.I | re.MULTILINE
        )
        if vc_m:
            vc = vc_m.group(1).strip()
    if not vc:
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
