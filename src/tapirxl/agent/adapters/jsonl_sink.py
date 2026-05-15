"""JSONL InventorySink — writes to the real stdout fd even under --json redirect."""
from __future__ import annotations

import json
import sys


class JsonlSink:
    def __init__(self, stream=None) -> None:
        self._out = stream if stream is not None else sys.stdout

    def write(self, row: dict, fused: dict | None) -> None:
        from tapirxl.agent.inventory import build_jsonl_record

        record = build_jsonl_record(row, fused, no_llm=fused is None)
        self._out.write(json.dumps(record, default=str))
        self._out.write("\n")
        self._out.flush()
