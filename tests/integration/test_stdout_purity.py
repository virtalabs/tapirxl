"""Regression: stdout carries the JSONL data contract; everything else stderr.

Drives `tapirxl parse` as a real subprocess so stdout and stderr are
independently observable (CliRunner merges them). Asserts that every byte
on stdout parses as a JSON object — no banners, summaries, warnings, or
third-party library noise.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent.parent / "fixtures" / "synthetic_philips_demo.pcap"


def _run_tapirxl_parse(*flags: str) -> tuple[str, str]:
    if not FIXTURE_PCAP.exists():
        pytest.skip(f"Fixture PCAP not found: {FIXTURE_PCAP}")
    proc = subprocess.run(
        [sys.executable, "-m", "tapirxl", "parse", str(FIXTURE_PCAP), *flags],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"tapirxl parse exited {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    return proc.stdout, proc.stderr


def _assert_pure_jsonl(stdout: str) -> list[dict]:
    records: list[dict] = []
    for lineno, line in enumerate(stdout.splitlines(), start=1):
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"stdout line {lineno} is not valid JSON (got {line!r}): {exc}"
            ) from exc
        assert isinstance(obj, dict), f"stdout line {lineno} is not a JSON object"
        records.append(obj)
    assert records, "Expected at least one JSON line on stdout"
    return records


class TestParseStdoutPurity:
    def test_default_mode_stdout_is_pure_host_envelope_jsonl(self) -> None:
        stdout, _ = _run_tapirxl_parse()
        records = _assert_pure_jsonl(stdout)
        for rec in records:
            assert "host_id" in rec, f"Expected HostEnvelope keys, got {sorted(rec)}"

    def test_json_mode_stdout_is_pure_inventory_record_jsonl(self) -> None:
        stdout, _ = _run_tapirxl_parse("--json")
        records = _assert_pure_jsonl(stdout)
        for rec in records:
            assert "mac_address" in rec, f"Expected InventoryRecord keys, got {sorted(rec)}"

    def test_summary_line_goes_to_stderr_not_stdout(self) -> None:
        stdout, stderr = _run_tapirxl_parse("--json")
        assert "packets scanned" not in stdout, "Pipeline summary leaked to stdout — N6 violation"
        assert "packets scanned" in stderr, (
            "Pipeline summary missing from stderr; expected progress reporting there"
        )
