"""Smoke test: `tapirxl parse <pcap>` emits schema-conformant HostEnvelope JSONL.

Mirror of test_smoke.py but for the typed envelope path (no ``--json``).
Confirms G1's flat-to-nested mapping survives end-to-end against the
synthetic Philips demo PCAP.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent.parent / "fixtures" / "synthetic_philips_demo.pcap"


def test_parse_emits_typed_host_envelopes() -> None:
    if not FIXTURE_PCAP.exists():
        pytest.skip(f"Fixture PCAP not found: {FIXTURE_PCAP}")

    from typer.testing import CliRunner

    from tapirxl.cli import app
    from tapirxl.schemas.envelope import HostEnvelope

    runner = CliRunner()
    result = runner.invoke(app, ["parse", str(FIXTURE_PCAP)])
    assert result.exit_code == 0, f"CLI exited {result.exit_code}:\n{result.output}"

    envelopes: list[HostEnvelope] = []
    for line in result.output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            env = HostEnvelope.model_validate_json(line)
        except Exception:
            continue
        envelopes.append(env)

    assert envelopes, "Expected at least one HostEnvelope JSONL line on stdout"

    for env in envelopes:
        assert env.host_id
        assert env.triage is not None
        if env.triage.routing is not None:
            assert env.triage.routing in {
                "SKIP",
                "STAMP_LOW",
                "DETERMINISTIC_FINAL",
                "AMBIGUOUS",
            }

    philips_hosts = [
        env
        for env in envelopes
        if env.pipeline_1
        and env.pipeline_1.ws_discovery
        and env.pipeline_1.ws_discovery.vendor_prefix_hex == "5048"
    ]
    assert philips_hosts, (
        "Expected at least one host with WS-Discovery vendor_prefix_hex == '5048' "
        "(Philips) in the synthetic demo PCAP"
    )
