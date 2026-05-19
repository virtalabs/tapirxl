"""Entry point for `tapirxl parse` — emits JSONL on stdout (or ``--output PATH``).

stdout carries the data contract only: ``HostEnvelope`` JSONL by default, or
``InventoryRecord`` JSONL with ``--json``. Every other byte — pyshark/tshark
warnings, third-party library noise, progress, summaries — is forced to
stderr by a defensive redirect during the extraction phase.

When ``output`` is set, the JSONL bytes go to that file (overwrite, UTF-8,
LF line endings) instead of stdout. Stdout emits nothing in that case;
stderr behavior is unchanged. Useful for one-shot container runs that
previously relied on shell redirection.
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path

from tapirxl.parser.pipeline import run


def _render(env: object, *, emit_inventory: bool) -> str:
    """Serialize a single runtime envelope to its JSONL line (no trailing newline)."""
    if emit_inventory:
        from tapirxl.core.inventory_record import build_jsonl_record

        return json.dumps(build_jsonl_record(env, fused=None, no_llm=True), default=str)

    from tapirxl.parser.serialize import to_envelope

    return to_envelope(env).model_dump_json()


def main(
    pcap: str,
    *,
    emit_inventory: bool = False,
    output: Path | None = None,
) -> None:
    real_stdout = sys.stdout
    with contextlib.redirect_stdout(sys.stderr):
        envelopes = run(pcap)

    # newline="\n" pins LF on all platforms so --output bytes match the stdout
    # golden byte-for-byte (defense-in-depth; CI/containers run Linux anyway).
    sink_fp = open(output, "w", encoding="utf-8", newline="\n") if output is not None else None
    try:
        target_fp = sink_fp if sink_fp is not None else real_stdout
        for env in envelopes:
            print(_render(env, emit_inventory=emit_inventory), file=target_fp)
            target_fp.flush()
    finally:
        if sink_fp is not None:
            sink_fp.close()
