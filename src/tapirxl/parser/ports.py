"""typing.Protocol definitions for the parser layer."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol


class PacketSource(Protocol):
    def packets(self) -> Iterator[object]: ...


class EnvelopeSink(Protocol):
    def write(self, envelope: dict) -> None: ...
