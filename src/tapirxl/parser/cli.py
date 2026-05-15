"""Entry point for `mdt parse` — emits one HostEnvelope JSON per line to stdout."""
from __future__ import annotations

import json
import sys

from tapirxl.parser.pipeline import run


def main(pcap: str) -> None:
    envelopes = run(pcap)
    for env in envelopes:
        print(json.dumps(env, default=str))
        sys.stdout.flush()
