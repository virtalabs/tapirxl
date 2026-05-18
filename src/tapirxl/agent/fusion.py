"""Layer 5 — LM-based signal fusion."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from tapirxl.agent.normalize import normalize_if_needed

_INTERNAL_SIGNAL_FIELDS = frozenset(
    {"_normalized", "_routing", "_processing_path", "_deterministic_preset", "_pkt_ts"}
)


def _lm_serialize(row: dict) -> str:
    from tapirxl.core.phi import redact_phi

    safe = redact_phi({k: v for k, v in row.items() if k not in _INTERNAL_SIGNAL_FIELDS})
    return json.dumps(safe, default=str)


def _fuse_host(row: dict, contradict_cot, fuse_module) -> dict:
    sig_json = _lm_serialize(row)

    try:
        c = contradict_cot(signal_register=sig_json)
        contradiction_flag = str(c.contradiction_flag).strip().lower() == "true"
        contradictions = [s.strip() for s in str(c.contradictions).split("|") if s.strip()]
    except Exception as e:
        print(f"\n  [warn] ContradictSignals failed for {row['ip']}: {e}", file=sys.stderr)
        contradiction_flag = False
        contradictions = []

    try:
        f = fuse_module(
            signal_register=sig_json,
            contradiction_flag="true" if contradiction_flag else "false",
            contradictions="|".join(contradictions),
            floor_triggers="|".join(row.get("floor_triggers", [])),
            expert_flags="|".join(row.get("expert_flags", [])),
        )
        device_class = str(f.device_class).strip()
        confidence = str(f.confidence).strip().upper()
        if confidence not in ("HIGH", "MEDIUM", "LOW"):
            confidence = "MEDIUM"
        if contradiction_flag and confidence == "HIGH":
            confidence = "MEDIUM"
        reasoning_trace = str(f.reasoning_trace).strip()
        open_questions = [s.strip() for s in str(f.open_questions).split("|") if s.strip()]
    except Exception as e:
        print(f"\n  [warn] FuseSignals failed for {row['ip']}: {e}", file=sys.stderr)
        device_class = "Unknown (fusion error)"
        confidence = "LOW"
        reasoning_trace = f"Fusion error: {e}"
        open_questions = []

    return {
        "host_id": row.get("host_id"),
        "mac": row.get("mac"),
        "ip": row["ip"],
        "_path": row.get("_processing_path", "FUSED"),
        "device_class": device_class,
        "confidence": confidence,
        "reasoning_trace": reasoning_trace,
        "open_questions": open_questions,
        "contradiction": contradiction_flag,
        "contradictions": contradictions,
    }


def run_fusion(
    fusion_queue: list[dict],
    norm_lm,
    fuse_lm,
    compiled_json: Path,
    compiled_normalize: Path,
    retriage_fn: Callable[[dict], None] | None = None,
) -> list[dict]:
    import dspy

    from tapirxl.agent.modules.fuse_module import FuseModule
    from tapirxl.agent.signatures.fuse import ContradictSignals

    normalize_if_needed(fusion_queue, norm_lm, compiled_normalize, retriage_fn=retriage_fn)

    spill: list[dict] = []
    pending: list[dict] = []
    for row in fusion_queue:
        if row.get("_processing_path") == "DETERMINISTIC_FINAL":
            preset = row.get("_deterministic_preset") or {}
            cons = row.get("triage", {}).get("deterministic_consensus") or {}
            dc = preset.get("device_class") or cons.get("label") or "Unknown deterministic"
            cc = preset.get("confidence") or cons.get("confidence") or "HIGH"
            spill.append(
                {
                    "host_id": row.get("host_id"),
                    "mac": row.get("mac"),
                    "ip": row["ip"],
                    "_path": "NORMALIZED_FINAL",
                    "device_class": dc,
                    "confidence": cc,
                    "reasoning_trace": (
                        "v2 deterministic re-route after normalization."
                        f" Consensus={json.dumps(cons)}"
                    ),
                    "open_questions": [],
                    "contradiction": bool(row.get("contradictions")),
                    "contradictions": row.get("contradictions", []) or [],
                }
            )
        else:
            pending.append(row)

    dspy.configure(lm=fuse_lm)
    fuse_module = FuseModule()
    if compiled_json.exists():
        try:
            fuse_module.load(str(compiled_json))
            print(f"  loaded compiled module from {compiled_json}", file=sys.stderr)
        except Exception as e:
            print(f"  [warn] could not load compiled module: {e} — zero-shot", file=sys.stderr)
    else:
        print(
            f"  [warn] {compiled_json} not found — using zero-shot (run --compile first)",
            file=sys.stderr,
        )

    contradict_cot = dspy.ChainOfThought(ContradictSignals)
    results: list[dict] = list(spill)
    for i, row in enumerate(pending, 1):
        print(
            f"  [{i}/{len(pending)}] fusing {row.get('host_id', '?')} @{row['ip']}...",
            file=sys.stderr,
        )
        results.append(_fuse_host(row, contradict_cot, fuse_module))
    return results


def _fuse_host_rlm(row: dict, fuse_module_rlm) -> dict:
    sig_json = _lm_serialize(row)
    try:
        f = fuse_module_rlm(
            signal_register=sig_json,
            floor_triggers="|".join(row.get("floor_triggers", [])),
            expert_flags="|".join(row.get("expert_flags", [])),
        )
        contradiction_flag = (
            str(getattr(f, "contradiction_flag", "false")).strip().lower() == "true"
        )
        contradictions = [
            s.strip() for s in str(getattr(f, "contradictions", "")).split("|") if s.strip()
        ]
        device_class = str(getattr(f, "device_class", "Unknown")).strip()
        confidence = str(getattr(f, "confidence", "MEDIUM")).strip().upper()
        if confidence not in ("HIGH", "MEDIUM", "LOW"):
            confidence = "MEDIUM"
        if contradiction_flag and confidence == "HIGH":
            confidence = "MEDIUM"
        reasoning_trace = str(getattr(f, "reasoning_trace", "")).strip()
        open_questions = [
            s.strip() for s in str(getattr(f, "open_questions", "")).split("|") if s.strip()
        ]
    except Exception as e:
        print(f"\n  [warn] FuseSignalsRLM failed for {row['ip']}: {e}", file=sys.stderr)
        contradiction_flag = False
        contradictions = []
        device_class = "Unknown (fusion error)"
        confidence = "LOW"
        reasoning_trace = f"Fusion error: {e}"
        open_questions = []

    return {
        "host_id": row.get("host_id"),
        "mac": row.get("mac"),
        "ip": row["ip"],
        "_path": "FUSED_RLM",
        "device_class": device_class,
        "confidence": confidence,
        "reasoning_trace": reasoning_trace,
        "open_questions": open_questions,
        "contradiction": contradiction_flag,
        "contradictions": contradictions,
    }


def run_fusion_rlm(
    fusion_queue: list[dict],
    norm_lm,
    fuse_lm,
    compiled_normalize: Path,
    compiled_json: Path,
    retriage_fn: Callable[[dict], None] | None = None,
) -> list[dict]:
    import dspy

    from tapirxl.agent.modules.fuse_module import FuseModuleRLM

    normalize_if_needed(fusion_queue, norm_lm, compiled_normalize, retriage_fn=retriage_fn)

    spill: list[dict] = []
    pending: list[dict] = []
    for row in fusion_queue:
        if row.get("_processing_path") == "DETERMINISTIC_FINAL":
            preset = row.get("_deterministic_preset") or {}
            cons = row.get("triage", {}).get("deterministic_consensus") or {}
            dc = preset.get("device_class") or cons.get("label") or "Unknown deterministic"
            cc = preset.get("confidence") or cons.get("confidence") or "HIGH"
            spill.append(
                {
                    "host_id": row.get("host_id"),
                    "mac": row.get("mac"),
                    "ip": row["ip"],
                    "_path": "NORMALIZED_FINAL",
                    "device_class": dc,
                    "confidence": cc,
                    "reasoning_trace": (
                        "v2 deterministic re-route after normalization (RLM path)."
                        f" Consensus={json.dumps(cons)}"
                    ),
                    "open_questions": [],
                    "contradiction": bool(row.get("contradictions")),
                    "contradictions": row.get("contradictions", []) or [],
                }
            )
        else:
            pending.append(row)

    dspy.configure(lm=fuse_lm)
    fuse_module_rlm = FuseModuleRLM(norm_lm)
    if compiled_json.exists():
        try:
            fuse_module_rlm.load(str(compiled_json))
            print(f"  loaded compiled fusion scaffold for RLM → {compiled_json}", file=sys.stderr)
        except Exception as e:
            print(f"  [warn] could not hydrate RLM from {compiled_json}: {e}", file=sys.stderr)

    results: list[dict] = list(spill)
    for i, row in enumerate(pending, 1):
        print(
            f"  [{i}/{len(pending)}] RLM fusing {row.get('host_id', '?')} @{row['ip']}...",
            file=sys.stderr,
        )
        results.append(_fuse_host_rlm(row, fuse_module_rlm))
    return results
