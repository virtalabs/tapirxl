"""M5 golden test: Jinja template output matches committed golden file."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent.parent / "fixtures" / "synthetic_philips_demo.pcap"
GOLDEN = Path(__file__).parent.parent / "fixtures" / "golden_report.md"

_DATE_RE = re.compile(r"\*\*Analysis date:\*\* `\d{4}-\d{2}-\d{2}`")
_DATE_PLACEHOLDER = "**Analysis date:** `DATE`"


def _normalise(text: str) -> str:
    """Replace the date line so the golden test doesn't fail day after day."""
    return _DATE_RE.sub(_DATE_PLACEHOLDER, text)


def test_golden_report(tmp_path: pytest.TempPathFactory) -> None:
    if not FIXTURE_PCAP.exists():
        pytest.skip(f"Fixture PCAP not found: {FIXTURE_PCAP}")
    if not GOLDEN.exists():
        pytest.skip(f"Golden file not found: {GOLDEN}")

    from typer.testing import CliRunner

    from tapirxl.cli import app

    runner = CliRunner()
    out_path = str(tmp_path / "report.md")
    result = runner.invoke(
        app,
        ["agent", str(FIXTURE_PCAP), "--no-llm", "--output", out_path],
    )
    assert result.exit_code == 0, f"CLI exited {result.exit_code}:\n{result.output}"

    actual = _normalise(Path(out_path).read_text())
    expected = _normalise(GOLDEN.read_text())

    assert actual == expected, (
        "Report does not match golden file.\n"
        "If the template changed intentionally, regenerate:\n"
        "  uv run mdt agent tests/fixtures/synthetic_philips_demo.pcap --no-llm "
        "--output tests/fixtures/golden_report.md"
    )
