"""Golden regression test — byte-identical CLI output for the demo PCAP.

D5 of the domain doc ("bit-identical replay") is the demo's central
technical promise. This test asserts that ``tapirxl parse`` against the
checked-in synthetic Philips PCAP produces the exact bytes recorded in the
two golden files in this directory.

The CLI is invoked via ``subprocess`` rather than ``typer.testing.CliRunner``
because the latter mixes stderr and stdout into a single capture stream; we
need real stdout fd separation to compare bytes against the golden.

**Toolchain dependency.** Byte-equality is sensitive to pyshark and tshark
versions. ``pyproject.toml`` pins ``pyshark==0.6``; ``tshark`` is a system
binary and is *not* pinned here. If this test fails on a development machine
after a tshark upgrade, regenerate with::

    just golden-regenerate

and inspect the diff before committing. Unintentional diffs indicate a
parser-output regression and should be investigated, not papered over.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURE_PCAP = REPO_ROOT / "tests" / "fixtures" / "synthetic_philips_demo.pcap"
GOLDEN_ENVELOPE = Path(__file__).parent / "golden_synthetic_philips_envelope.jsonl"
GOLDEN_INVENTORY = Path(__file__).parent / "golden_synthetic_philips_inventory.jsonl"


def _run_parse(extra_args: list[str]) -> bytes:
    """Invoke `tapirxl parse <fixture> [extra]` and return raw stdout bytes."""
    proc = subprocess.run(
        [sys.executable, "-m", "tapirxl", "parse", str(FIXTURE_PCAP), *extra_args],
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return proc.stdout


def _run_parse_to_file(out_path: Path, extra_args: list[str]) -> bytes:
    """Invoke `tapirxl parse <fixture> --output <out_path> [extra]`.

    Asserts stdout is empty (the --output contract) and returns the bytes
    written to the file.
    """
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tapirxl",
            "parse",
            str(FIXTURE_PCAP),
            *extra_args,
            "--output",
            str(out_path),
        ],
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    )
    assert proc.stdout == b"", (
        "tapirxl parse --output must emit nothing on stdout (N6: stdout is the "
        f"data contract). Got {len(proc.stdout)} bytes: {proc.stdout[:200]!r}"
    )
    return out_path.read_bytes()


def _diff_message(golden_path: Path, actual: bytes, expected: bytes) -> str:
    """Build a helpful failure message naming the regeneration recipe."""
    return (
        f"\nGolden mismatch against {golden_path.relative_to(REPO_ROOT)}.\n"
        f"  expected bytes: {len(expected)}\n"
        f"  actual bytes:   {len(actual)}\n"
        "If the diff is intentional (parser change), regenerate with:\n"
        "  just golden-regenerate\n"
        "and review the diff before committing. Otherwise investigate the regression "
        "— this test guards D5 (bit-identical replay).\n"
    )


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Fixture PCAP missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ENVELOPE.exists(), reason=f"Golden missing: {GOLDEN_ENVELOPE}")
def test_golden_envelope_byte_identical() -> None:
    actual = _run_parse([])
    expected = GOLDEN_ENVELOPE.read_bytes()
    assert actual == expected, _diff_message(GOLDEN_ENVELOPE, actual, expected)


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Fixture PCAP missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_INVENTORY.exists(), reason=f"Golden missing: {GOLDEN_INVENTORY}")
def test_golden_inventory_byte_identical() -> None:
    actual = _run_parse(["--json"])
    expected = GOLDEN_INVENTORY.read_bytes()
    assert actual == expected, _diff_message(GOLDEN_INVENTORY, actual, expected)


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Fixture PCAP missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ENVELOPE.exists(), reason=f"Golden missing: {GOLDEN_ENVELOPE}")
def test_golden_envelope_output_flag_byte_identical(tmp_path: Path) -> None:
    """`--output PATH` writes the same bytes as the stdout path (HostEnvelope JSONL)."""
    out_path = tmp_path / "envelope.jsonl"
    actual = _run_parse_to_file(out_path, [])
    expected = GOLDEN_ENVELOPE.read_bytes()
    assert actual == expected, _diff_message(GOLDEN_ENVELOPE, actual, expected)


@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Fixture PCAP missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_INVENTORY.exists(), reason=f"Golden missing: {GOLDEN_INVENTORY}")
def test_golden_inventory_output_flag_byte_identical(tmp_path: Path) -> None:
    """`--json --output PATH` writes the same bytes as the stdout path (InventoryRecord JSONL)."""
    out_path = tmp_path / "inventory.jsonl"
    actual = _run_parse_to_file(out_path, ["--json"])
    expected = GOLDEN_INVENTORY.read_bytes()
    assert actual == expected, _diff_message(GOLDEN_INVENTORY, actual, expected)
