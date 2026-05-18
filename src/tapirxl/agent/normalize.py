"""Layer 4 — conditional normalization of ambiguous fields."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from tapirxl.core.ws_tables import (
    KNOWN_WS_TYPES_PREFIXES,
    PHILIPS_MDNS_TXT_KEYWORDS,
    PHILIPS_WS_TYPES_CANONICAL,
)


def _fields_needing_normalization(
    row: dict, skip: set[str] | None = None
) -> list[tuple[str, str, str]]:
    skip = skip if skip is not None else set()
    items: list[tuple[str, str, str]] = []
    for t in row.get("ws_types", []):
        if t in skip:
            continue
        if not any(t.startswith(pfx) for pfx in KNOWN_WS_TYPES_PREFIXES):
            items.append(("ws_types", t, "WS_DISCOVERY"))
    for entry in row.get("mdns_txt_raw", []):
        if entry in skip:
            continue
        if "=" not in entry and entry.strip():
            items.append(("mdns_txt_raw", entry, "MDNS_TXT"))
    return items


def apply_philips_deterministic_normalization(row: dict) -> set[str]:
    """Philips-scoped deterministic normalization. Returns raw values resolved (skip LLM)."""
    resolved: set[str] = set()
    for t in row.get("ws_types", []):
        if not t:
            continue
        for prefix, label in PHILIPS_WS_TYPES_CANONICAL.items():
            if t.startswith(prefix):
                row.setdefault("ws_types_normalized", {})[t] = label
                resolved.add(t)
                break
    for entry in row.get("mdns_txt_raw", []):
        if not entry.strip() or "=" in entry:
            continue
        for keyword, norm_key, norm_value in PHILIPS_MDNS_TXT_KEYWORDS:
            if keyword in entry:
                row["mdns_txt_parsed"].setdefault(norm_key, norm_value)
                resolved.add(entry)
                break
    return resolved


def _lm_serialize_shard(row: dict, keys: tuple[str, ...]) -> str:
    from tapirxl.core.phi import redact_phi

    return json.dumps(redact_phi({k: row.get(k) for k in keys if k in row}))


def normalize_if_needed(
    fusion_queue: list[dict],
    norm_lm,
    compiled_normalize: Path,
    retriage_fn: Callable[[dict], None] | None = None,
) -> None:
    """Normalize ambiguous fields in-place; optionally re-route each row.

    `retriage_fn` is injected by the entry-point CLI (see N1 — `agent/`
    must not import `parser/`). When `None`, hosts retain whatever
    `_processing_path` they had on entry; this is the documented behavior
    for the standalone `mdt-agent` stdin path that consumes already-routed
    envelopes from upstream.
    """
    import dspy

    from tapirxl.agent.modules.norm_module import NormModule

    norm_module = NormModule()
    dspy.configure(lm=norm_lm)
    if compiled_normalize.exists():
        try:
            norm_module.load(str(compiled_normalize))
            print(f"  loaded NormalizeSignal demos from {compiled_normalize}", file=sys.stderr)
        except Exception as e:
            print(f"  [warn] normalize compile load failed: {e}", file=sys.stderr)
    else:
        print(
            f"  [warn] {compiled_normalize} missing — zero-shot NormalizeSignal",
            file=sys.stderr,
        )

    keys_ctx = ("host_id", "ip", "mac", "oui_vendor", "triage", "pipeline_1")
    for row in fusion_queue:
        resolved = apply_philips_deterministic_normalization(row)
        ambiguous = list(row.get("lm_envelope", {}).get("ambiguous_fields") or [])
        if not ambiguous:
            for field_path, raw_value, proto in _fields_needing_normalization(row, skip=resolved):
                ambiguous.append(
                    {
                        "raw_value": raw_value,
                        "source_protocol": proto,
                        "field_path": field_path,
                        "candidate_labels": ["OTHER:KEEP_VERBATIM"],
                        "host_context": row.get("host_id", ""),
                    }
                )

        envelope_ctx = _lm_serialize_shard(row, keys_ctx)

        for af in ambiguous:
            raw_val = af.get("raw_value", "")
            if raw_val in resolved:
                continue
            bundle = json.dumps(af, default=str)
            try:
                result = norm_module(
                    ambiguous_field_bundle=bundle,
                    envelope_context=envelope_ctx,
                )
                nv_raw = str(getattr(result, "normalized_value", "")).strip()
                cand = list(af.get("candidate_labels") or [])
                conf = str(getattr(result, "confidence", "LOW")).strip().upper()
                if nv_raw not in cand and not nv_raw.upper().startswith("OTHER:"):
                    conf = "MEDIUM"

                fp = af.get("field_path", "")
                if fp == "mdns_txt_raw":
                    row["mdns_txt_parsed"].setdefault(f"_llm_{str(raw_val)[:32]}", nv_raw)
                elif fp == "ws_types":
                    row.setdefault("ws_types_normalized", {})[raw_val] = nv_raw
                row.setdefault("_normalized", []).append(
                    {"field": fp, "raw": raw_val, "norm": nv_raw, "confidence": conf}
                )
            except Exception as e:
                print(
                    f"\n  [warn] normalization failed for {row.get('ip')}: {e}",
                    file=sys.stderr,
                )

        row.setdefault("lm_envelope", {})["ambiguous_fields"] = []
        row.pop("_routing", None)
        if retriage_fn is not None:
            retriage_fn(row)
