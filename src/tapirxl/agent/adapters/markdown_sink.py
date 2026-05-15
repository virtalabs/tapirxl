"""Writes markdown inventory to reports/."""
from __future__ import annotations

import sys
from pathlib import Path


class MarkdownSink:
    def __init__(self, out_path: Path) -> None:
        self._path = out_path

    def open(self, header: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("w", encoding="utf-8")
        self._fh.write(header)

    def write_record(self, rendered: str) -> None:
        self._fh.write(rendered)

    def close(self) -> None:
        self._fh.close()
        print(f"  report → {self._path}", file=sys.stderr)
