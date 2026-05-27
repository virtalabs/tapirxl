"""Per-pipeline deterministic labeling and consensus aggregation."""

from __future__ import annotations


def _subsumes_label(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    if "MX700" in a and "IntelliVue" in b:
        return True
    return False


def _consensus_from_pipelines(env: dict) -> tuple[str | None, str]:
    labels: list[tuple[str, str, int]] = []
    for name in ("pipeline_1", "pipeline_2", "pipeline_3"):
        blk = env.get(name) or {}
        lbl = blk.get("deterministic_label")
        conf = blk.get("deterministic_confidence", "LOW")
        if lbl:
            rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(conf, 1)
            labels.append((lbl, conf, rank))
    if not labels:
        return None, "LOW"

    highs = [(lbl, c) for lbl, c, _r in labels if c == "HIGH"]
    mids = [(lbl, c) for lbl, c, _r in labels if c == "MEDIUM"]

    if len(highs) >= 2:
        base_l = highs[0][0]
        agreement = all(
            base_l == other or _subsumes_label(base_l, other) or _subsumes_label(other, base_l)
            for other, _oc in highs[1:]
        )
        if agreement:
            return base_l, "HIGH"

    if len(highs) == 1 and not mids:
        return highs[0][0], "HIGH"

    if len(highs) == 1 and mids:
        return highs[0][0], "MEDIUM"

    if mids:
        return mids[0][0], "MEDIUM"

    return labels[-1][0], labels[-1][1]


def label_pipeline_1(env: dict) -> None:
    p1 = env.get("pipeline_1")
    if not p1:
        return
    cand: list[tuple[str, str]] = []
    if env.get("ws_series_family"):
        cand.append((env["ws_series_family"], "HIGH"))
    for obs in env.get("ssdp_observations", []) or []:
        for h in obs.get("hints") or []:
            if "Sonos" in h:
                cand.append(("Sonos networked speaker / controller ecosystem", "HIGH"))
    if env.get("capsule_mdip", {}).get("tokens"):
        cand.append(("Capsule MDIP / Philips patient connectivity middleware", "HIGH"))
    if env.get("arp_bindings"):
        cand.append(("Layer-2 Ethernet endpoint (ARP observed)", "LOW"))
    lbl, conf = "", ""
    high = [(lbl2, c) for lbl2, c in cand if c == "HIGH"]
    if len(high) >= 1:
        lbl, conf = high[0]
    elif cand:
        lbl, conf = cand[0]
    p1["deterministic_label"] = lbl or ""
    p1["deterministic_confidence"] = conf or "LOW"


def label_pipeline_2(env: dict) -> None:
    p2 = env.get("pipeline_2")
    if not p2:
        return
    label = ""
    conf = "LOW"
    feats = []
    last_syn_cf = "LOW"
    for syn in p2.get("syn_fingerprints") or []:
        sf = syn.get("deterministic_syn_label")
        if sf:
            feats.append(sf)
        last_syn_cf = syn.get("confidence_hint", last_syn_cf) or last_syn_cf
    if feats:
        label = feats[-1]
        conf = last_syn_cf if last_syn_cf in ("HIGH", "MEDIUM", "LOW") else "LOW"
    tls_hits = []
    for tls in p2.get("sni_hits") or []:
        tls_hits.extend(tls.get("ecosystem_hints") or [])
    if tls_hits:
        uniq = "|".join(sorted(set(tls_hits)))
        label = uniq or label
        if conf == "LOW":
            conf = "MEDIUM"
    if env.get("_ssh_banners"):
        label = ("SSH-managed host; " + (label or "").strip()).strip("; ") or "SSH-managed host"
    p2["deterministic_label"] = label or ""
    p2["deterministic_confidence"] = conf


def label_pipeline_3(env: dict) -> None:
    p3 = env.get("pipeline_3")
    if not p3:
        return
    label = ""
    conf = "LOW"
    dhcp_hits = []
    for dhcp in p3.get("dhcp") or []:
        dhcp_hits.append(dhcp.get("vendor_medical_hint") or dhcp.get("fingerbank_dhcp_hit"))
    dhcp_hits = [h for h in dhcp_hits if h]
    if dhcp_hits:
        label = dhcp_hits[0]
        conf = "MEDIUM"
    dicom_hints = []
    for dicom in p3.get("dicom_association") or []:
        assoc = dicom.get("dicom_association") or {}
        for s in assoc.get("sop_class_hints") or []:
            if "->" in s:
                dicom_hints.append(s.split("->", 1)[1])
    if any("Philips" in h for h in dicom_hints):
        label = "Philips modality / DICOM-speaking device"
        conf = "HIGH"
    elif any("GE" in h for h in dicom_hints):
        label = "GE modality / DICOM-speaking device"
        conf = "HIGH"
    snmp_hits = [s.get("deterministic_descr_label") for s in p3.get("snmp_sysdescr") or []]
    snmp_hits = [s for s in snmp_hits if s]
    if snmp_hits and not label:
        label = snmp_hits[0]
        conf = "MEDIUM"

    hl7_hints = []
    for hl7 in p3.get("hl7_segments") or []:
        if hl7.get("sending_facility_normalized_hint"):
            hl7_hints.append(hl7["sending_facility_normalized_hint"])
    if hl7_hints:
        label = hl7_hints[0] or label
        conf = "MEDIUM"

    p3["deterministic_label"] = label or ""
    p3["deterministic_confidence"] = conf


def postprocess_pipeline_labels(env: dict) -> None:
    label_pipeline_1(env)
    label_pipeline_2(env)
    label_pipeline_3(env)
