"""stdout JSONL EnvelopeSink."""

from __future__ import annotations

import sys

from tapirxl.schemas.envelope import HostEnvelope


class StdoutSink:
    def write(self, envelope: HostEnvelope) -> None:
        print(envelope.model_dump_json(), file=sys.stdout)
        sys.stdout.flush()
