"""Entry point for mdt-agent — consumes HostEnvelope JSONL from stdin."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path

_COMPILED_JSON_DEFAULT = Path("agents/compiled_fusion.json")
_COMPILED_NORMALIZE_DEFAULT = Path("agents/compiled_normalize.json")


def _partition_by_routing(
    register: list[dict],
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Split pre-routed envelopes into (skip, stamp_low, deterministic, fusion_queue)."""
    skip: list[dict] = []
    stamp_low: list[dict] = []
    deterministic: list[dict] = []
    fusion_queue: list[dict] = []
    for row in register:
        routing = (row.get("triage") or {}).get("routing")
        if routing == "SKIP":
            skip.append(row)
        elif routing == "STAMP_LOW":
            stamp_low.append(row)
        elif routing == "DETERMINISTIC_FINAL":
            deterministic.append(row)
        else:
            fusion_queue.append(row)
    return skip, stamp_low, deterministic, fusion_queue


def run_agent(
    register: list[dict],
    *,
    no_llm: bool,
    compiled_json: Path,
    compiled_normalize: Path,
    emit_json: bool,
    rlm: bool,
    filter_threshold: str,
    pcap_stem: str,
    output: Path | None,
    jsonl_stdout=None,
    cfg=None,
    retriage_fn: Callable[[dict], None] | None = None,
) -> None:
    """Core agent execution: triage → normalize → fuse → output.

    `retriage_fn` is supplied by the wiring CLI (the only places allowed to
    bridge `agent/` and `parser/` per CLAUDE.md N1). When `None`, Layer-4
    normalization runs without re-routing.
    """
    print("Layer 3: triage gate...", file=sys.stderr)
    skip_hosts, stamp_low, deterministic_hosts, fusion_queue = _partition_by_routing(register)
    print(
        f"  SKIP={len(skip_hosts)}  STAMP_LOW={len(stamp_low)}"
        f"  DETERMINISTIC_FINAL={len(deterministic_hosts)}  LM_QUEUE={len(fusion_queue)}",
        file=sys.stderr,
    )

    fusion_results: list[dict] = []
    if not no_llm and fusion_queue:
        from tapirxl.agent.adapters.ollama_lm import build_lm_pair

        fuse_lm, norm_lm = build_lm_pair(cfg)

        print("Layer 4: normalization (conditional)...", file=sys.stderr)
        if rlm:
            from tapirxl.agent.fusion import run_fusion_rlm

            print(f"Layer 5: RLM fusion ({len(fusion_queue)} hosts)...", file=sys.stderr)
            fusion_results = run_fusion_rlm(
                fusion_queue,
                norm_lm,
                fuse_lm,
                compiled_normalize,
                compiled_json,
                retriage_fn=retriage_fn,
            )
        else:
            from tapirxl.agent.fusion import run_fusion

            print(f"Layer 5: fusion ({len(fusion_queue)} hosts)...", file=sys.stderr)
            fusion_results = run_fusion(
                fusion_queue,
                norm_lm,
                fuse_lm,
                compiled_json,
                compiled_normalize,
                retriage_fn=retriage_fn,
            )
    elif no_llm:
        print("  --no-llm: skipping normalization and fusion", file=sys.stderr)

    if emit_json:
        from tapirxl.agent.inventory import emit_jsonl_to_stdout

        print("Layer 6: emitting JSONL inventory to stdout...", file=sys.stderr)
        emit_jsonl_to_stdout(
            stamp_low + deterministic_hosts + fusion_queue,
            fusion_results,
            stream=jsonl_stdout,
            no_llm=no_llm,
        )
        print("\nDone. Inventory emitted as JSONL on stdout.", file=sys.stderr)
    else:
        from tapirxl.agent.inventory import write_inventory

        if output:
            out_path = output
        else:
            today_str = date.today().strftime("%Y%m%d")
            out_path = Path.cwd() / "reports" / f"asset_inventory_{pcap_stem}_{today_str}.md"

        print("Layer 6: writing inventory...", file=sys.stderr)
        write_inventory(
            out_path,
            skip_hosts,
            stamp_low,
            deterministic_hosts,
            fusion_queue,
            fusion_results,
            pcap_stem,
            no_llm,
            filter_threshold=filter_threshold,
        )
        print(f"\nDone. Report: {out_path}", file=sys.stderr)


def main() -> None:
    """mdt-agent entry point — reads HostEnvelope JSONL from stdin."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="mdt-agent",
        description="Agent layer: normalize + fuse + report. Reads envelopes from stdin.",
    )
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--compile", action="store_true")
    parser.add_argument("--compile-normalize", action="store_true")
    parser.add_argument("--compiled-json", default=str(_COMPILED_JSON_DEFAULT))
    parser.add_argument("--compiled-normalize-json", default=str(_COMPILED_NORMALIZE_DEFAULT))
    parser.add_argument("--output", default=None)
    parser.add_argument("--rlm", action="store_true")
    parser.add_argument("--filter", choices=["H", "M", "L"], default="L")
    parser.add_argument("--json", action="store_true", dest="emit_json")
    parser.add_argument("--models", default=None, metavar="PATH")
    args = parser.parse_args()

    _jsonl_stdout = None
    if args.emit_json:
        _jsonl_stdout = sys.stdout
        sys.stdout = sys.stderr

    compiled_json = Path(args.compiled_json)
    compiled_normalize = Path(args.compiled_normalize_json)

    cfg = None
    if not args.no_llm:
        from tapirxl.agent.config import load_model_config

        cfg = load_model_config(Path(args.models) if args.models else None)

    if args.compile_normalize:
        import dspy

        from tapirxl.agent.adapters.ollama_lm import build_lm_pair
        from tapirxl.agent.compile.compile_normalize import run_compile_normalize

        _, norm_lm = build_lm_pair(cfg)
        dspy.configure(lm=norm_lm)
        print("Running BootstrapFewShot compilation (NormalizeSignal)...", file=sys.stderr)
        run_compile_normalize(compiled_normalize)
        if not args.compile:
            return

    if args.compile:
        import dspy

        from tapirxl.agent.adapters.ollama_lm import build_lm_pair
        from tapirxl.agent.compile.compile_fusion import run_compile

        fuse_lm, _ = build_lm_pair(cfg)
        dspy.configure(lm=fuse_lm)
        print("Running BootstrapFewShot compilation (FuseSignals)...", file=sys.stderr)
        run_compile(compiled_json)
        return

    # Read envelopes from stdin
    register: list[dict] = []
    for line in sys.stdin:
        line = line.strip()
        if line:
            register.append(json.loads(line))

    print(f"  {len(register)} host envelopes (from stdin)", file=sys.stderr)

    # N1 bridge: parser/triage is imported only at the entry-point wiring layer.
    from tapirxl.parser.triage import retriage_after_normalization

    run_agent(
        register,
        no_llm=args.no_llm,
        compiled_json=compiled_json,
        compiled_normalize=compiled_normalize,
        emit_json=args.emit_json,
        rlm=args.rlm,
        filter_threshold=args.filter,
        pcap_stem="stdin",
        output=Path(args.output) if args.output else None,
        jsonl_stdout=_jsonl_stdout,
        cfg=cfg,
        retriage_fn=retriage_after_normalization,
    )
