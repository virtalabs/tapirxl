"""Entry point for `tapirxl parse` — emits JSONL on stdout.

stdout carries the data contract only: ``HostEnvelope`` JSONL by default, or
``InventoryRecord`` JSONL with ``--json``. Every other byte — pyshark/tshark
warnings, third-party library noise, progress, summaries — is forced to
stderr by a defensive redirect during the extraction phase.
"""

from __future__ import annotations

import contextlib
import json
import sys

from tapirxl.parser.pipeline import run


def main(pcap: str, *, emit_inventory: bool = False) -> None:
    real_stdout = sys.stdout
    with contextlib.redirect_stdout(sys.stderr):
        envelopes = run(pcap)

    if emit_inventory:
        from tapirxl.core.inventory_record import build_jsonl_record

        for env in envelopes:
            record = build_jsonl_record(env, fused=None, no_llm=True)
            print(json.dumps(record, default=str), file=real_stdout)
            real_stdout.flush()
    else:
        from tapirxl.parser.serialize import to_envelope

        for env in envelopes:
            envelope = to_envelope(env)
            print(envelope.model_dump_json(), file=real_stdout)
            real_stdout.flush()
