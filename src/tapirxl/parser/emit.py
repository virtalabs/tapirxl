"""Shared JSONL serialization for parser and live emit paths."""

from __future__ import annotations

import json


def render_envelope(env: object, *, emit_inventory: bool) -> str:
    """Serialize a single runtime envelope to its JSONL line (no trailing newline)."""
    if emit_inventory:
        from tapirxl.core.inventory_record import build_jsonl_record

        return json.dumps(build_jsonl_record(env, fused=None, no_llm=True), default=str)

    from tapirxl.parser.serialize import to_envelope

    return to_envelope(env).model_dump_json()
