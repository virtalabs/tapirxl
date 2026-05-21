"""Per-MAC live emission state machine for ``tapirxl listen``."""

from __future__ import annotations

import heapq
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from tapirxl.core.mac import normalize_mac
from tapirxl.parser.deterministic import postprocess_pipeline_labels
from tapirxl.parser.emit import render_envelope
from tapirxl.parser.envelope_builder import (
    finalize_envelope_from_records,
    make_empty_envelope,
    merge_record_into_envelope,
)
from tapirxl.parser.triage import contradiction_scan, route_host

# MACs that are never a real asset and must be dropped before envelope creation.
# The all-zero MAC appears on Linux loopback (lo has no hardware address) and
# is the only artifact distinguishing live capture from PCAP file capture for
# the synthetic fixture; ignoring it keeps the live and pcap paths in lock-step.
_NON_HOST_MACS = frozenset({"00:00:00:00:00:00"})


class HostPhase(Enum):
    INITIAL_BUFFER = "initial_buffer"
    STABLE = "stable"


@dataclass
class HostState:
    envelope: dict[str, Any]
    phase: HostPhase
    last_signal_at: float
    last_emit_at: float | None = None
    dirty_since_emit: bool = False


class LiveEmitter:
    """Accumulates per-packet records and emits complete envelopes on schedule."""

    def __init__(
        self,
        oui_table: dict[str, str],
        *,
        initial_emit_secs: float = 2.0,
        quiescence_secs: float = 30.0,
        heartbeat_secs: float = 300.0,
        emit_inventory: bool = False,
        on_emit: Callable[[str], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.oui_table = oui_table
        self.initial_emit_secs = initial_emit_secs
        self.quiescence_secs = quiescence_secs
        self.heartbeat_secs = heartbeat_secs
        self.emit_inventory = emit_inventory
        self._on_emit = on_emit or (lambda _line: None)
        self._clock = clock or time.monotonic

        self.hosts: dict[str, HostState] = {}
        self._deadlines: list[tuple[float, int, str, str]] = []
        self._seq = 0

    def now(self) -> float:
        return self._clock()

    def _schedule(self, mac: str, deadline: float, reason: str) -> None:
        self._seq += 1
        heapq.heappush(self._deadlines, (deadline, self._seq, mac, reason))

    def _cancel_reasons(self, mac: str, reasons: set[str]) -> None:
        if not self._deadlines:
            return
        self._deadlines = [
            item for item in self._deadlines if not (item[2] == mac and item[3] in reasons)
        ]
        heapq.heapify(self._deadlines)

    def _arm_heartbeat(self, mac: str) -> None:
        self._cancel_reasons(mac, {"heartbeat"})
        self._schedule(mac, self.now() + self.heartbeat_secs, "heartbeat")

    def ingest_record(self, record: dict[str, Any]) -> None:
        mac = normalize_mac(record.get("src_mac") or "")
        if not mac or mac in _NON_HOST_MACS:
            return

        now = self.now()
        state = self.hosts.get(mac)
        if state is None:
            state = HostState(
                envelope=make_empty_envelope(mac, self.oui_table),
                phase=HostPhase.INITIAL_BUFFER,
                last_signal_at=now,
                dirty_since_emit=True,
            )
            self.hosts[mac] = state
            self._schedule(mac, now + self.initial_emit_secs, "initial")

        merge_record_into_envelope(state.envelope, record)
        state.last_signal_at = now
        state.dirty_since_emit = True

        if state.phase is HostPhase.STABLE:
            self._cancel_reasons(mac, {"quiescence"})
            self._schedule(mac, now + self.quiescence_secs, "quiescence")

    def process_due_events(self, *, until: float | None = None) -> None:
        limit = self.now() if until is None else until
        while self._deadlines and self._deadlines[0][0] <= limit:
            _deadline, _seq, mac, reason = heapq.heappop(self._deadlines)
            state = self.hosts.get(mac)
            if state is None:
                continue

            if reason == "initial" and state.phase is HostPhase.INITIAL_BUFFER:
                self._emit(mac, state)
                state.phase = HostPhase.STABLE
                self._schedule(mac, self.now() + self.quiescence_secs, "quiescence")
                self._arm_heartbeat(mac)
            elif reason == "quiescence" and state.phase is HostPhase.STABLE:
                if state.dirty_since_emit:
                    self._emit(mac, state)
                    self._arm_heartbeat(mac)
            elif reason == "heartbeat" and state.phase is HostPhase.STABLE:
                self._emit(mac, state)
                self._arm_heartbeat(mac)

    def drain(self) -> None:
        for mac, state in self.hosts.items():
            if state.phase is HostPhase.INITIAL_BUFFER or state.dirty_since_emit:
                self._emit(mac, state)
                state.phase = HostPhase.STABLE
                state.dirty_since_emit = False

    def next_deadline(self) -> float | None:
        if not self._deadlines:
            return None
        return self._deadlines[0][0]

    def _emit(self, mac: str, state: HostState) -> None:
        env = state.envelope
        finalize_envelope_from_records(env)
        contradiction_scan(env)
        postprocess_pipeline_labels(env)
        route_host(env)
        line = render_envelope(env, emit_inventory=self.emit_inventory)
        state.last_emit_at = self.now()
        state.dirty_since_emit = False
        self._on_emit(line)
