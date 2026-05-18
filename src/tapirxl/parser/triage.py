"""Cross-pipeline contradiction detection, routing, and triage gate."""

from __future__ import annotations

from tapirxl.parser.deterministic import _consensus_from_pipelines, postprocess_pipeline_labels
from tapirxl.parser.tables import (
    CONTRADICTION_MESSAGES,
    KNOWN_WS_TYPES_PREFIXES,
    PHILIPS_MDNS_TXT_KEYWORDS,
    PHILIPS_WS_TYPES_CANONICAL,
)


def _attach_ambiguous_candidates(env: dict, field_entry: dict) -> None:
    env.setdefault("lm_envelope", {"ambiguous_fields": []})
    env["lm_envelope"]["ambiguous_fields"].append(field_entry)


def contradiction_scan(env: dict) -> None:
    env["contradictions"] = []
    env["triage"]["contradiction_codes"] = []
    oui = (env.get("oui_vendor") or "").lower()
    p3_dicom_vendor = ""
    for d in (env.get("pipeline_3") or {}).get("dicom_association") or []:
        assoc = d.get("dicom_association") or {}
        for hit in assoc.get("sop_class_hints") or []:
            low = hit.lower()
            if "philips" in low:
                p3_dicom_vendor = "Philips"
            if "siemens" in low:
                p3_dicom_vendor = "Siemens"
            if "ge" in low:
                p3_dicom_vendor = "GE"
    # C1
    if p3_dicom_vendor and oui:
        mismatch = (
            "philips" in p3_dicom_vendor.lower()
            and oui.strip()
            and "philips" not in oui
            and "unknown" not in oui.lower()
            and oui.upper()[:3].isalnum()
        )
        if mismatch:
            env["contradictions"].append(CONTRADICTION_MESSAGES["C1"])
            env["triage"]["contradiction_codes"].append("C1")
    mdns_txt_join = "\n".join(env.get("mdns_txt_raw") or [])
    chromecast = (
        "chromecast" in mdns_txt_join.lower() or "cast" in (env.get("mdns_hostname") or "").lower()
    )
    philips_signals = env.get("ws_vendor_prefix") in {"5048", "4745", "5349", "4452", "4243"}
    # C2
    if chromecast and philips_signals:
        env["contradictions"].append(CONTRADICTION_MESSAGES["C2"])
        env["triage"]["contradiction_codes"].append("C2")

    ws_types_join = "\n".join(env.get("ws_types") or [])
    philips_ws = philips_signals or ("philips" in ws_types_join.lower())
    dicom_hints_lc: list[str] = []
    for d in (env.get("pipeline_3") or {}).get("dicom_association") or []:
        assoc = d.get("dicom_association") or {}
        for hint in assoc.get("sop_class_hints") or []:
            if not hint:
                continue
            lab = hint.split("->")[-1] if "->" in hint else hint
            dicom_hints_lc.append(str(lab).lower())
    dicom_arc_non_philips = any(
        ("siemens" in h or ("ge" in h and "philips" not in h)) and "philips" not in h
        for h in dicom_hints_lc
    )
    if philips_ws and dicom_arc_non_philips:
        env["contradictions"].append(CONTRADICTION_MESSAGES["C3"])
        env["triage"]["contradiction_codes"].append("C3")

    # C4
    mdns_h = (env.get("mdns_hostname") or "").split(".")[0].lower()
    ll_h = (env.get("llmnr_hostname") or "").split(".")[0].lower()
    if mdns_h and ll_h and mdns_h not in ll_h and ll_h not in mdns_h:
        env["contradictions"].append(CONTRADICTION_MESSAGES["C4"])
        env["triage"]["contradiction_codes"].append("C4")


def route_host(env: dict) -> None:
    consensus_lbl, consensus_conf = _consensus_from_pipelines(env)
    env["triage"]["deterministic_consensus"] = (
        {"label": consensus_lbl, "confidence": consensus_conf} if consensus_lbl else None
    )

    amb = env.setdefault("lm_envelope", {"ambiguous_fields": []})["ambiguous_fields"]
    amb.clear()

    for t in env.get("ws_types", []):
        if not t or any(t.startswith(pfx) for pfx in KNOWN_WS_TYPES_PREFIXES):
            continue
        amb.append(
            {
                "raw_value": t,
                "source_protocol": "WS_DISCOVERY",
                "field_path": "ws_types",
                "candidate_labels": [
                    *list(PHILIPS_WS_TYPES_CANONICAL.values()),
                    "OTHER:KEEP_VERBATIM",
                ],
                "host_context": env.get("host_id", ""),
            }
        )
    for entry in env.get("mdns_txt_raw", []):
        if "=" in entry or not entry.strip():
            continue
        amb.append(
            {
                "raw_value": entry,
                "source_protocol": "MDNS_TXT",
                "field_path": "mdns_txt_raw",
                "candidate_labels": [v for _k, _nk, v in PHILIPS_MDNS_TXT_KEYWORDS]
                + ["OTHER:KEEP_VERBATIM"],
                "host_context": env.get("host_id", ""),
            }
        )

    env["triage"]["contradiction_codes"] = env["triage"].get("contradiction_codes", [])

    # Routing per ARCHITECTURE.md §6.1 / CLAUDE.md, first-match-wins.
    #
    # Note: contradictions are handled as an early-exit to ENQUEUE_FUSION even
    # though the literal spec only forbids DETERMINISTIC_FINAL via "not contra".
    # The defensive read keeps contradictory hosts off the deterministic path
    # and out of STAMP_LOW (where their contradiction would be lost).

    if env["signal_count"] == 0 and not env["expert_flags"]:
        env["triage"]["routing"] = "SKIP"
        env["_processing_path"] = "SKIP"
        return

    if env["triage"].get("contradiction_codes"):
        env["triage"]["routing"] = "ENQUEUE_FUSION"
        env["_processing_path"] = "ENQUEUE_FUSION"
        return

    if env["signal_count"] == 1 and not env["floor_triggers"]:
        env["triage"]["routing"] = "STAMP_LOW"
        env["_processing_path"] = "STAMP_LOW"
        return

    if consensus_conf == "HIGH" and consensus_lbl and not amb:
        env["triage"]["routing"] = "DETERMINISTIC_FINAL"
        env["_processing_path"] = "DETERMINISTIC_FINAL"
        env["_deterministic_preset"] = {
            "device_class": consensus_lbl,
            "confidence": "HIGH",
        }
        return

    if amb:
        env["triage"]["routing"] = (
            "ENQUEUE_FULL"
            if env.get("pipeline_3") and env.get("pipeline_2") and consensus_lbl is None
            else "ENQUEUE_NORMALIZE"
        )
        env["_processing_path"] = env["triage"]["routing"]
        return

    if consensus_lbl and consensus_conf != "HIGH":
        env["triage"]["routing"] = "ENQUEUE_FULL"
        env["_processing_path"] = "ENQUEUE_FULL"
    else:
        env["triage"]["routing"] = "ENQUEUE_FUSION"
        env["_processing_path"] = "ENQUEUE_FUSION"


def triage_gate(
    register: list[dict],
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    skip: list[dict] = []
    stamp_low: list[dict] = []
    fusion_queue: list[dict] = []
    deterministic: list[dict] = []

    for row in register:
        routing = row.get("triage", {}).get("routing")
        if routing == "SKIP":
            skip.append(row)
        elif routing == "STAMP_LOW":
            stamp_low.append(row)
        elif routing == "DETERMINISTIC_FINAL":
            deterministic.append(row)
        else:
            fusion_queue.append(row)

    return skip, stamp_low, deterministic, fusion_queue


def retriage_after_normalization(host: dict) -> None:
    """Re-score routing after deterministic + LLM normalization touched ambiguous fields."""
    host.setdefault("lm_envelope", {"ambiguous_fields": []})
    contradiction_scan(host)
    postprocess_pipeline_labels(host)
    route_host(host)
