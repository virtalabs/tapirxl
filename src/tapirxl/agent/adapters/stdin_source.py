"""Reads HostEnvelope JSONL from stdin."""
from __future__ import annotations

import json
import sys
from collections.abc import Iterator


class StdinSource:
    def envelopes(self) -> Iterator[dict]:
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield json.loads(line)
