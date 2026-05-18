"""Entry point for `mdt parse` — emits JSONL on stdout.

Default output: one HostEnvelope JSON per line (the raw deterministic shape
from the parser pipeline). With ``emit_inventory=True``, the output is one
InventoryRecord per line conforming to ``schemas/inventory_record.schema.json``.
"""
from __future__ import annotations

import json
import sys

from tapirxl.parser.pipeline import run


def main(pcap: str, *, emit_inventory: bool = False) -> None:
    envelopes = run(pcap)
    if emit_inventory:
        from tapirxl.core.inventory_record import build_jsonl_record

        for env in envelopes:
            record = build_jsonl_record(env, fused=None, no_llm=True)
            print(json.dumps(record, default=str))
            sys.stdout.flush()
    else:
        for env in envelopes:
            print(json.dumps(env, default=str))
            sys.stdout.flush()
