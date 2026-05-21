"""Unit tests for the live per-MAC emission state machine."""

from __future__ import annotations

from tapirxl.core.mac import normalize_mac
from tapirxl.parser.live_emitter import HostPhase, LiveEmitter


def _record(mac: str, *, ts: float = 1.0, proto: str = "ARP") -> dict:
    return {
        "src_mac": mac,
        "protocol": proto,
        "timestamp": ts,
        "raw_fields": {"protocol": proto},
    }


def _fake_clock(start: float = 0.0):
    t = {"now": start}

    def _now() -> float:
        return t["now"]

    def advance(by: float) -> None:
        t["now"] += by

    return _now, advance


def test_initial_buffer_emits_after_settle_window() -> None:
    clock, advance = _fake_clock()
    lines: list[str] = []
    emitter = LiveEmitter(
        {},
        initial_emit_secs=2.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record("aa:bb:cc:dd:ee:01", ts=0.0))
    assert lines == []
    advance(2.0)
    emitter.process_due_events()
    assert len(lines) == 1
    assert emitter.hosts["AA:BB:CC:DD:EE:01"].phase is HostPhase.STABLE


def test_quiescence_re_emits_after_new_signals() -> None:
    clock, advance = _fake_clock()
    lines: list[str] = []
    mac = "aa:bb:cc:dd:ee:02"
    emitter = LiveEmitter(
        {},
        initial_emit_secs=0.0,
        quiescence_secs=5.0,
        heartbeat_secs=999.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record(mac, ts=0.0))
    emitter.process_due_events()
    assert len(lines) == 1

    emitter.ingest_record(_record(mac, ts=1.0, proto="MDNS_A"))
    advance(5.0)
    emitter.process_due_events()
    assert len(lines) == 2


def test_heartbeat_emits_under_continuous_traffic() -> None:
    clock, advance = _fake_clock()
    lines: list[str] = []
    mac = "aa:bb:cc:dd:ee:03"
    emitter = LiveEmitter(
        {},
        initial_emit_secs=0.0,
        quiescence_secs=999.0,
        heartbeat_secs=10.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record(mac, ts=0.0))
    emitter.process_due_events()
    assert len(lines) == 1

    for i in range(1, 6):
        advance(2.0)
        emitter.ingest_record(_record(mac, ts=float(i * 2), proto="MDNS_A"))
        emitter.process_due_events()

    advance(10.0)
    emitter.process_due_events()
    assert len(lines) >= 2


def test_drain_emits_dirty_hosts_on_shutdown() -> None:
    clock, advance = _fake_clock()
    lines: list[str] = []
    mac = "aa:bb:cc:dd:ee:04"
    emitter = LiveEmitter(
        {},
        initial_emit_secs=5.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record(mac, ts=0.0))
    emitter.drain()
    assert len(lines) == 1
    advance(10.0)
    emitter.process_due_events()
    assert len(lines) == 1


def test_accumulates_signals_across_emissions() -> None:
    clock, advance = _fake_clock()
    lines: list[str] = []
    mac = "aa:bb:cc:dd:ee:05"
    emitter = LiveEmitter(
        {},
        initial_emit_secs=0.0,
        quiescence_secs=1.0,
        heartbeat_secs=999.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record(mac, ts=0.0, proto="ARP"))
    emitter.process_due_events()
    first_count = emitter.hosts[normalize_mac(mac)].envelope.get("signal_count", 0)

    emitter.ingest_record(_record(mac, ts=0.5, proto="MDNS_A"))
    advance(1.0)
    emitter.process_due_events()

    second_env = emitter.hosts[normalize_mac(mac)].envelope
    assert second_env.get("signal_count", 0) >= first_count
