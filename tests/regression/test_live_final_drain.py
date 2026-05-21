"""Live-mode final drain must match pcap goldens per MAC."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tapirxl.core.oui import load_oui_table
from tapirxl.parser.live_emitter import LiveEmitter
from tapirxl.parser.pipeline import extract_packets
from tapirxl.schemas.envelope import HostEnvelope
from tapirxl.schemas.inventory import InventoryRecord

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURE_PCAP = REPO_ROOT / "tests" / "fixtures" / "synthetic_philips_demo.pcap"
GOLDEN_ENVELOPE = Path(__file__).parent / "golden_synthetic_philips_envelope.jsonl"
GOLDEN_INVENTORY = Path(__file__).parent / "golden_synthetic_philips_inventory.jsonl"


def _load_golden_by_mac(path: Path, *, key: str) -> dict[str, dict]:
    rows = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    return {row[key]: row for row in rows}


def _last_emission_by_mac(emitter: LiveEmitter, *, inventory: bool) -> dict[str, dict]:
    by_mac: dict[str, dict] = {}
    for _mac, state in emitter.hosts.items():
        if not state.emissions:
            continue
        line = state.emissions[-1]
        obj = json.loads(line)
        lookup_key = "mac_address" if inventory else "host_id"
        by_mac[obj[lookup_key]] = obj
    return by_mac


def _signal_count(obj: dict) -> int:
    if "signal_count" in obj:
        return int(obj["signal_count"])
    if "triage" in obj and isinstance(obj["triage"], dict):
        return int(obj["triage"].get("signal_count") or 0)
    return 0


def _monotonic_signal_counts(emissions: list[str]) -> None:
    prev = -1
    for line in emissions:
        obj = json.loads(line)
        if "host_id" in obj:
            HostEnvelope.model_validate(obj)
            count = _signal_count(obj)
        else:
            InventoryRecord.model_validate(obj)
            count = _signal_count(obj) if "signal_count" in obj else prev + 1
        assert count >= prev, f"signal_count regressed: {prev} -> {count}"
        prev = count


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Missing fixture: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ENVELOPE.exists(), reason=f"Missing golden: {GOLDEN_ENVELOPE}")
def test_live_final_drain_envelope_matches_golden() -> None:
    oui_table = load_oui_table(REPO_ROOT / "static" / "ieee_oui.txt")
    records = sorted(
        extract_packets(str(FIXTURE_PCAP), oui_table),
        key=lambda r: float(r.get("timestamp", 0)),
    )

    clock = {"now": 0.0}

    def _now() -> float:
        return clock["now"]

    emitter = LiveEmitter(
        oui_table,
        initial_emit_secs=0.0,
        quiescence_secs=1.0,
        heartbeat_secs=99999.0,
        emit_inventory=False,
        clock=_now,
    )

    for rec in records:
        ts = float(rec.get("timestamp", 0))
        clock["now"] = ts
        emitter.ingest_record(rec)
        emitter.process_due_events(until=ts)

    clock["now"] = float(records[-1]["timestamp"]) + 100.0
    emitter.process_due_events()
    emitter.drain()

    for state in emitter.hosts.values():
        _monotonic_signal_counts(state.emissions)

    actual = _last_emission_by_mac(emitter, inventory=False)
    expected = _load_golden_by_mac(GOLDEN_ENVELOPE, key="host_id")
    assert set(actual) == set(expected)
    for mac in expected:
        assert actual[mac] == expected[mac], f"Envelope mismatch for {mac}"


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Missing fixture: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_INVENTORY.exists(), reason=f"Missing golden: {GOLDEN_INVENTORY}")
def test_live_final_drain_inventory_matches_golden() -> None:
    oui_table = load_oui_table(REPO_ROOT / "static" / "ieee_oui.txt")
    records = sorted(
        extract_packets(str(FIXTURE_PCAP), oui_table),
        key=lambda r: float(r.get("timestamp", 0)),
    )

    clock = {"now": 0.0}

    def _now() -> float:
        return clock["now"]

    emitter = LiveEmitter(
        oui_table,
        initial_emit_secs=0.0,
        quiescence_secs=1.0,
        heartbeat_secs=99999.0,
        emit_inventory=True,
        clock=_now,
    )

    for rec in records:
        ts = float(rec.get("timestamp", 0))
        clock["now"] = ts
        emitter.ingest_record(rec)
        emitter.process_due_events(until=ts)

    clock["now"] = float(records[-1]["timestamp"]) + 100.0
    emitter.process_due_events()
    emitter.drain()

    for state in emitter.hosts.values():
        _monotonic_signal_counts(state.emissions)

    actual = _last_emission_by_mac(emitter, inventory=True)
    expected = _load_golden_by_mac(GOLDEN_INVENTORY, key="mac_address")
    assert set(actual) == set(expected)
    for mac in expected:
        assert actual[mac] == expected[mac], f"Inventory mismatch for {mac}"
