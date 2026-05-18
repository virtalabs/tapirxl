"""stdout JSONL EnvelopeSink."""

from __future__ import annotations

import json
import sys


class StdoutSink:
    def write(self, envelope: dict) -> None:
        print(json.dumps(envelope, default=str), file=sys.stdout)
        sys.stdout.flush()
