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


def test_zero_mac_loopback_traffic_is_dropped() -> None:
    """Live capture on Linux ``lo`` surfaces zero-MAC packets; never emit them.

    Regression: the live integration smoke saw 9 hosts (8 synthetic + the
    loopback interface itself) because the all-zero MAC has no hardware
    address. The emitter must filter it before envelope creation so the
    live and pcap paths agree on the same MAC set.
    """
    clock, _advance = _fake_clock()
    lines: list[str] = []
    emitter = LiveEmitter(
        {},
        initial_emit_secs=0.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record("00:00:00:00:00:00", ts=0.0))
    emitter.process_due_events()
    emitter.drain()

    assert lines == []
    assert "00:00:00:00:00:00" not in emitter.hosts


def test_heartbeat_not_duplicated_after_quiescence_emit() -> None:
    """Regression: a quiescence-driven emit must not stack a second heartbeat.

    Bug: prior to this test, scheduling a fresh heartbeat in the quiescence
    branch without cancelling the existing one caused the heap to retain two
    heartbeats per host forever, so the effective cadence was ~quiescence_secs
    faster than the configured heartbeat_secs.
    """
    clock, advance = _fake_clock()
    lines: list[str] = []
    mac = "aa:bb:cc:dd:ee:06"
    emitter = LiveEmitter(
        {},
        initial_emit_secs=2.0,
        quiescence_secs=30.0,
        heartbeat_secs=300.0,
        emit_inventory=True,
        on_emit=lines.append,
        clock=clock,
    )

    emitter.ingest_record(_record(mac, ts=0.0))
    advance(2.0)
    emitter.process_due_events()
    assert len(lines) == 1

    advance(3.0)
    emitter.ingest_record(_record(mac, ts=5.0, proto="MDNS_A"))
    advance(30.0)
    emitter.process_due_events()
    assert len(lines) == 2

    pending_heartbeats = sum(1 for _d, _s, _m, r in emitter._deadlines if r == "heartbeat")
    assert pending_heartbeats == 1, (
        f"Expected exactly one pending heartbeat per host, got {pending_heartbeats}"
    )

    advance(1000.0)
    emitter.process_due_events()
    extra = len(lines) - 2
    assert extra <= 4, (
        f"Heartbeat cadence violated: {extra} heartbeat emits in 1000s "
        f"with heartbeat_secs=300 (expected at most 4)"
    )
