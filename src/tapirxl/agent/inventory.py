"""Layer 6 — inventory output: markdown report and JSONL stream."""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

from tapirxl.core.enums import (
    CPE_PRODUCT_ENUM,
    CPE_VENDOR_ENUM,
    DEVICE_CLASS_ENUM,
    enum_or_none,
    to_cpe_product,
    to_cpe_vendor,
    to_device_class,
)
from tapirxl.core.inventory_record import (
    CONF_RANK,
    _derive_hostname,
    _effective_inventory_conf,
    build_jsonl_record,
)
from tapirxl.core.ip import ip_sort_key


def _record_fuse_key(row: dict) -> str:
    return str(row.get("host_id") or row.get("ip") or row.get("mac") or "unknown")


def _classification_for_record(row: dict, fused: dict | None, no_llm: bool) -> tuple[str, str]:
    if fused and not no_llm:
        return (
            fused.get("device_class", "Unknown"),
            fused.get("confidence", "LOW"),
        )
    routing = row.get("triage", {}).get("routing") or ""
    cons = row.get("triage", {}).get("deterministic_consensus") or {}
    if not no_llm and routing == "DETERMINISTIC_FINAL" and cons.get("label"):
        return str(cons.get("label")), str(cons.get("confidence", "HIGH"))
    if routing == "STAMP_LOW":
        return "Likely benign / weak-signal endpoint (routing STAMP_LOW)", "LOW"
    if row.get("signal_count") == 1 and not row.get("floor_triggers"):
        return "Unclassified (single signal)", "LOW"
    return "Unclassified (triage only)", "TRIAGE_ONLY"


def _format_pipeline_doc(name: str, block: dict | None) -> list[str]:
    if not block:
        return [f"- **{name}:** *(not triggered)*"]
    lbl = block.get("deterministic_label") or "—"
    conf = block.get("deterministic_confidence", "LOW")
    snippet = json.dumps(block, indent=2, default=str)
    return [
        f"- **{name}:** deterministic `{lbl}` (**{conf}**)",
        f"```json\n{snippet}\n```",
    ]


def _one_signal_summary(row: dict) -> str:
    if row.get("ws_uuid"):
        return f"WS-Discovery UUID: {row['ws_uuid']}"
    if row.get("mdns_hostname"):
        return f"mDNS hostname: {row['mdns_hostname']}"
    if row.get("dns_sd_services"):
        return f"DNS-SD: {row['dns_sd_services'][0]}"
    if row.get("llmnr_queries"):
        return f"LLMNR query: {row['llmnr_queries'][0]}"
    return "single broadcast signal (type unknown)"


def emit_jsonl_to_stdout(
    rows: list[dict],
    fusion_results: list[dict],
    stream=None,
    no_llm: bool = True,
) -> None:
    out = stream if stream is not None else sys.stdout
    fused_by_key = {_record_fuse_key(r): r for r in fusion_results}
    for row in rows:
        fused = fused_by_key.get(_record_fuse_key(row))
        record = build_jsonl_record(row, fused, no_llm=no_llm)
        out.write(json.dumps(record, default=str))
        out.write("\n")
        out.flush()


def _render_record(row: dict, fusion: dict | None, no_llm: bool) -> str:
    ip = row["ip"]
    device_class, confidence = _classification_for_record(row, fusion, no_llm)
    hostname = _derive_hostname(row) or "—"
    cpe_vendor = enum_or_none(to_cpe_vendor(row), CPE_VENDOR_ENUM) or "—"
    cpe_product = enum_or_none(to_cpe_product(row), CPE_PRODUCT_ENUM) or "—"
    enum_device_class = enum_or_none(to_device_class(row), DEVICE_CLASS_ENUM) or "—"

    tri = row.get("triage") or {}
    proc_path = fusion.get("_path") if fusion else row.get("_processing_path")
    pipelines_fired = tri.get("pipelines_fired") or []
    if not pipelines_fired:
        pipelines_fired = [
            pn for pn in ("pipeline_1", "pipeline_2", "pipeline_3") if row.get(pn) is not None
        ]
    cons = tri.get("deterministic_consensus") or {}

    lines = [
        f"## {ip} — {device_class}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| IP | `{ip}` |",
        f"| MAC | `{row.get('mac') or '—'}` |",
        f"| Host ID | `{row.get('host_id') or '—'}` |",
        f"| OUI Vendor | {row.get('oui_vendor', 'UNKNOWN')} |",
        f"| Hostname | {hostname} |",
        f"| Vendor (CPE) | `{cpe_vendor}` |",
        f"| Product (CPE) | `{cpe_product}` |",
        f"| Device class (enum) | `{enum_device_class}` |",
        f"| Pipelines fired | `{', '.join(str(p) for p in pipelines_fired) or '—'}` |",
        f"| Processing path | `{proc_path or '—'}` |",
        f"| Triage routing | `{tri.get('routing') or '—'}` |",
        f"| Deterministic consensus | `{cons.get('label') or '—'}"
        f" ({cons.get('confidence') or '—'})` |",
        f"| Confidence | **{confidence}** |",
        f"| Device Class | {device_class} |",
        "",
        "### Pipeline blocks (deterministic excerpts)",
        "",
    ]
    for pn in ("pipeline_1", "pipeline_2", "pipeline_3"):
        lines.extend(_format_pipeline_doc(pn.upper(), row.get(pn)))
        lines.append("")

    lines += [
        "### Broadcast / legacy flat summary",
        "",
        f"- SSDP hints: `{json.dumps(row.get('ssdp_observations') or [], default=str)[:280]}` …",
        f"- WS-Discovery UUID: `{row.get('ws_uuid') or '—'}`",
        f"- WS-Discovery Types: {', '.join(row.get('ws_types', []) or []) or '—'}",
        f"- mDNS hostname: {row.get('mdns_hostname') or '—'}",
        "- mDNS TXT: "
        + (json.dumps(row.get("mdns_txt_parsed") or {}) if row.get("mdns_txt_parsed") else "—"),
        f"- DNS-SD services: {', '.join(row.get('dns_sd_services', []) or []) or '—'}",
        f"- LLMNR queries: {', '.join(row.get('llmnr_queries', []) or []) or '—'}",
        f"- LLMNR hostname: {row.get('llmnr_hostname') or '—'}",
        "",
        "**Contradictions (deterministic codes):**",
        "; ".join(tri.get("contradiction_codes") or []) or "None",
        "",
        "**Expert Anomalies:** " + ("; ".join(row.get("expert_flags") or []) or "None"),
        "",
    ]

    ccodes = "; ".join(tri.get("contradiction_codes") or []) or ""
    cdet = "; ".join(row.get("contradictions") or []) or ""
    if ccodes or cdet:
        lines += ["**Contradictions (expanded):**", "", cdet or "(see codes)", ""]

    if row["signal_count"] == 1 and not row["floor_triggers"]:
        lines += [
            f"> Single signal: {_one_signal_summary(row)}. "
            "Insufficient for multi-signal classification without further capture.",
            "",
        ]

    nh = row.get("_normalized") or []
    if nh and not no_llm:
        lines += ["**Normalization trace:**", "```json\n" + json.dumps(nh) + "\n```", ""]

    if not no_llm and fusion:
        lines += [
            "**Fusion reasoning:**",
            "",
            fusion.get("reasoning_trace", ""),
            "",
            "**Open Questions:**",
            "",
        ]
        oqs = fusion.get("open_questions", []) or []
        lines += [f"- {q}" for q in oqs] if oqs else ["- None"]
        lines += [
            "",
            "**Contradictions (fusion pass):** "
            + ("; ".join(fusion.get("contradictions") or []) or "None"),
            "",
        ]

    lines += ["---", ""]
    return "\n".join(lines)


def to_report_view(envelope: dict, fusion: dict | None, no_llm: bool) -> dict:
    """Build a flat view-model dict for one host record. No markdown in here."""
    device_class, confidence = _classification_for_record(envelope, fusion, no_llm)
    tri = envelope.get("triage") or {}
    cons = tri.get("deterministic_consensus") or {}

    pipelines_fired = tri.get("pipelines_fired") or [
        pn for pn in ("pipeline_1", "pipeline_2", "pipeline_3") if envelope.get(pn) is not None
    ]

    pipeline_blocks = []
    for pn in ("pipeline_1", "pipeline_2", "pipeline_3"):
        block = envelope.get(pn)
        if block:
            pipeline_blocks.append({
                "name": pn.upper(),
                "is_triggered": True,
                "label": block.get("deterministic_label") or "—",
                "confidence": block.get("deterministic_confidence", "LOW"),
                "snippet_json": json.dumps(block, indent=2, default=str),
            })
        else:
            pipeline_blocks.append({"name": pn.upper(), "is_triggered": False})

    ccodes = "; ".join(tri.get("contradiction_codes") or [])
    cdet = "; ".join(envelope.get("contradictions") or [])
    has_contradictions_expanded = bool(ccodes or cdet)

    single_signal = envelope.get("signal_count") == 1 and not envelope.get("floor_triggers")

    fusion_view = None
    if not no_llm and fusion:
        oqs = fusion.get("open_questions", []) or []
        fusion_view = {
            "reasoning_trace": fusion.get("reasoning_trace", ""),
            "open_questions": oqs,
            "contradictions": "; ".join(fusion.get("contradictions") or []) or "None",
        }

    nh = envelope.get("_normalized") or []
    normalized_json_str = json.dumps(nh) if (nh and not no_llm) else None

    return {
        "ip": envelope["ip"],
        "device_class": device_class,
        "confidence": confidence,
        "mac": envelope.get("mac") or "—",
        "host_id": envelope.get("host_id") or "—",
        "oui_vendor": envelope.get("oui_vendor", "UNKNOWN"),
        "hostname": _derive_hostname(envelope) or "—",
        "cpe_vendor": enum_or_none(to_cpe_vendor(envelope), CPE_VENDOR_ENUM) or "—",
        "cpe_product": enum_or_none(to_cpe_product(envelope), CPE_PRODUCT_ENUM) or "—",
        "device_class_enum": enum_or_none(to_device_class(envelope), DEVICE_CLASS_ENUM) or "—",
        "pipelines_fired_str": ", ".join(str(p) for p in pipelines_fired) or "—",
        "proc_path": (fusion.get("_path") if fusion else envelope.get("_processing_path")) or "—",
        "triage_routing": tri.get("routing") or "—",
        "consensus_label": cons.get("label") or "—",
        "consensus_confidence": cons.get("confidence") or "—",
        "pipeline_blocks": pipeline_blocks,
        "ssdp_hints": json.dumps(envelope.get("ssdp_observations") or [], default=str)[:280],
        "ws_uuid": envelope.get("ws_uuid") or "—",
        "ws_types_str": ", ".join(envelope.get("ws_types", []) or []) or "—",
        "mdns_hostname": envelope.get("mdns_hostname") or "—",
        "mdns_txt": (
            json.dumps(envelope.get("mdns_txt_parsed") or {})
            if envelope.get("mdns_txt_parsed")
            else "—"
        ),
        "dns_sd_services_str": ", ".join(envelope.get("dns_sd_services", []) or []) or "—",
        "llmnr_queries_str": ", ".join(envelope.get("llmnr_queries", []) or []) or "—",
        "llmnr_hostname": envelope.get("llmnr_hostname") or "—",
        "contradiction_codes": "; ".join(tri.get("contradiction_codes") or []) or "None",
        "expert_flags": "; ".join(envelope.get("expert_flags") or []) or "None",
        "has_contradictions_expanded": has_contradictions_expanded,
        "contradictions_expanded": cdet or "(see codes)",
        "single_signal": single_signal,
        "single_signal_text": _one_signal_summary(envelope) if single_signal else None,
        "normalized_json_str": normalized_json_str,
        "fusion": fusion_view,
    }


def _find_templates_dir() -> Path:
    candidates = [
        Path.cwd() / "templates",
        Path(__file__).parent.parent.parent.parent / "templates",
    ]
    for p in candidates:
        if p.is_dir():
            return p
    return Path.cwd() / "templates"


def write_inventory(
    out_path: Path,
    skip: list[dict],
    stamp_low: list[dict],
    deterministic_hosts: list[dict],
    fusion_queue: list[dict],
    fusion_results: list[dict],
    pcap_path: str,
    no_llm: bool,
    filter_threshold: str = "L",
) -> None:
    import jinja2

    fused_by_key = {_record_fuse_key(r): r for r in fusion_results}

    records_to_render: list[tuple[dict, dict | None]] = []
    for row in stamp_low:
        records_to_render.append((row, None))
    for row in deterministic_hosts:
        records_to_render.append((row, fused_by_key.get(_record_fuse_key(row))))
    for row in fusion_queue:
        records_to_render.append((row, fused_by_key.get(_record_fuse_key(row))))

    filt = filter_threshold.upper()
    filt_key = filt if filt in ("H", "M", "L") else "L"
    min_rank_needed = CONF_RANK[{"H": "HIGH", "M": "MEDIUM", "L": "LOW"}[filt_key]]

    records_to_render = [
        (r, f) for r, f in records_to_render
        if CONF_RANK.get(_effective_inventory_conf(r, f, no_llm), 1) >= min_rank_needed
    ]

    def _sort_key(item: tuple) -> tuple:
        row, fused = item
        ec = _effective_inventory_conf(row, fused, no_llm)
        return (CONF_RANK.get(ec, 1), ip_sort_key(row["ip"]))

    records_to_render.sort(key=_sort_key)

    if not no_llm:
        high_c = sum(1 for _, f in records_to_render if f and f.get("confidence") == "HIGH")
        med_c = sum(1 for _, f in records_to_render if f and f.get("confidence") == "MEDIUM")
        low_c = sum(1 for _, f in records_to_render if f and f.get("confidence", "LOW") == "LOW")
        low_c += sum(
            1 for r, f in records_to_render
            if f is None and _effective_inventory_conf(r, f, no_llm) == "LOW"
        )
        tri_c = sum(
            1 for r, f in records_to_render
            if _effective_inventory_conf(r, f, no_llm) == "TRIAGE_ONLY"
        )
        conf_counts = {"high": high_c, "medium": med_c, "low_total": low_c + tri_c}
    else:
        low_c = sum(
            1 for r, f in records_to_render if _effective_inventory_conf(r, f, True) == "LOW"
        )
        tri_c = sum(
            1
            for r, f in records_to_render
            if _effective_inventory_conf(r, f, True) == "TRIAGE_ONLY"
        )
        conf_counts = {"low": low_c, "triage_only": tri_c}

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_find_templates_dir())),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    template = env.get_template("report_template.md.jinja")

    context = {
        "pcap_name": Path(pcap_path).name,
        "today": date.today().isoformat(),
        "mode": " | ".join([
            "triage-only (--no-llm)" if no_llm else "full pipeline (LM fusion)",
            f"output confidence filter `{filt_key}` (min rank `{min_rank_needed}`)",
        ]),
        "no_llm": no_llm,
        "totals": {
            "hosts": len(skip) + len(stamp_low) + len(deterministic_hosts) + len(fusion_queue),
            "skipped": len(skip),
            "stamp_low": len(stamp_low),
            "deterministic_final": len(deterministic_hosts),
            "lm_queued": len(fusion_queue),
        },
        "conf_counts": conf_counts,
        "records": [to_report_view(r, f, no_llm) for r, f in records_to_render],
        "skip_rows": [
            {"ip": r["ip"], "mac": r.get("mac") or "—",
             "oui_vendor": r.get("oui_vendor", "UNKNOWN")}
            for r in sorted(skip, key=lambda r: ip_sort_key(r["ip"]))
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(template.render(**context), encoding="utf-8")
    print(f"  report → {out_path}", file=sys.stderr)
