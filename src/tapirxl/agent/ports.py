"""typing.Protocol definitions for the agent layer."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol


class LMRunner(Protocol):
    def __call__(self, **kwargs) -> object: ...


class EnvelopeSource(Protocol):
    def envelopes(self) -> Iterator[dict]: ...


class InventorySink(Protocol):
    def write(self, row: dict, fused: dict | None) -> None: ...
