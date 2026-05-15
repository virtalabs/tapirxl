"""M1 smoke test: mdt agent --no-llm on synthetic fixture produces a non-empty report."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent.parent / "fixtures" / "synthetic_philips_demo.pcap"
REPORTS_DIR = Path.cwd() / "reports"


def test_agent_no_llm_produces_report(tmp_path: pytest.TempPathFactory) -> None:
    if not FIXTURE_PCAP.exists():
        pytest.skip(f"Fixture PCAP not found: {FIXTURE_PCAP}")

    from typer.testing import CliRunner

    from tapirxl.cli import app

    runner = CliRunner()
    out_path = str(tmp_path / "report.md")
    result = runner.invoke(
        app,
        ["agent", str(FIXTURE_PCAP), "--no-llm", "--output", out_path],
    )
    assert result.exit_code == 0, f"CLI exited {result.exit_code}:\n{result.output}"

    report = Path(out_path)
    assert report.exists(), "Report file was not created"
    content = report.read_text()
    assert len(content) > 500, "Report is suspiciously short"
    assert "MAC" in content, "Expected MAC field in report"
    assert "8" in content or "host" in content.lower(), "Expected host count in report"
