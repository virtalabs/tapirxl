"""Golden regression test — byte-identical CLI output for the SonoSite fixture PCAP."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURE_PCAP = REPO_ROOT / "tests" / "fixtures" / "sonosite_us_scenario.pcap"
GOLDEN_ENVELOPE = Path(__file__).parent / "golden_sonosite_us_envelope.jsonl"
GOLDEN_INVENTORY = Path(__file__).parent / "golden_sonosite_us_inventory.jsonl"


def _run_parse(extra_args: list[str]) -> bytes:
    proc = subprocess.run(
        [sys.executable, "-m", "tapirxl", "parse", str(FIXTURE_PCAP), *extra_args],
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return proc.stdout


def _diff_message(golden_path: Path, actual: bytes, expected: bytes) -> str:
    return (
        f"\nGolden mismatch against {golden_path.relative_to(REPO_ROOT)}.\n"
        f"  expected bytes: {len(expected)}\n"
        f"  actual bytes:   {len(actual)}\n"
        "If the diff is intentional (parser change), regenerate with:\n"
        "  just golden-regenerate-sonosite\n"
        "and review the diff before committing.\n"
    )


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Fixture PCAP missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ENVELOPE.exists(), reason=f"Golden missing: {GOLDEN_ENVELOPE}")
def test_golden_sonosite_envelope_byte_identical() -> None:
    actual = _run_parse([])
    expected = GOLDEN_ENVELOPE.read_bytes()
    assert actual == expected, _diff_message(GOLDEN_ENVELOPE, actual, expected)


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Fixture PCAP missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_INVENTORY.exists(), reason=f"Golden missing: {GOLDEN_INVENTORY}")
def test_golden_sonosite_inventory_byte_identical() -> None:
    actual = _run_parse(["--json"])
    expected = GOLDEN_INVENTORY.read_bytes()
    assert actual == expected, _diff_message(GOLDEN_INVENTORY, actual, expected)
