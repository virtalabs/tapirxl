"""Phase 1 integration smoke: ``tapirxl:demo-dev`` → Vector → stub BlueFlow.

Exercises the production Vector config (not dryrun) with ``--network=host``
so the container can reach ``127.0.0.1:<stub-port>``. Mirrors the 2026-05-18
live BlueFlow smoke (8x201 first-write, 8x200 idempotent re-run) without
requiring a real BlueFlow instance.

Linux + Docker only (``--network=host`` is not supported on Docker Desktop
for Mac the same way). CI runs this on ``ubuntu-latest``; macOS dev machines
skip and use ``just docker-dry-run-demo`` instead.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.integration.blueflow_stub import BlueFlowStub

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURE_PCAP = REPO_ROOT / "tests" / "fixtures" / "synthetic_philips_demo.pcap"
GOLDEN_ASSETS = REPO_ROOT / "tests" / "regression" / "golden_synthetic_philips_assets.jsonl"
DEMO_DOCKERFILE = REPO_ROOT / "packaging" / "docker" / "demo" / "Dockerfile"
DEMO_IMAGE_TAG = "tapirxl:demo-dev"
SMOKE_TOKEN = "smoke-token"
EXPECTED_MAC_COUNT = 8


def _docker_daemon_available() -> bool:
    if shutil.which("docker") is None:
        return False
    proc = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    return proc.returncode == 0


def _build_demo_image() -> None:
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(DEMO_DOCKERFILE.relative_to(REPO_ROOT)),
            "-t",
            DEMO_IMAGE_TAG,
            ".",
        ],
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
        timeout=600,
    )


def _run_demo_container(*, port: int) -> subprocess.CompletedProcess[bytes]:
    fixtures_dir = FIXTURE_PCAP.parent.resolve()
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=host",
            "-v",
            f"{fixtures_dir}:/pcap:ro",
            "-e",
            "TAPIRXL_MODE=pcap",
            "-e",
            f"TAPIRXL_PCAP_PATH=/pcap/{FIXTURE_PCAP.name}",
            "-e",
            f"BLUEFLOW_URL=http://127.0.0.1:{port}",
            "-e",
            f"BLUEFLOW_TOKEN={SMOKE_TOKEN}",
            DEMO_IMAGE_TAG,
        ],
        capture_output=True,
        check=False,
        timeout=180,
    )


def _golden_payloads_by_mac() -> dict[str, dict]:
    lines = GOLDEN_ASSETS.read_text(encoding="utf-8").splitlines()
    payloads = [json.loads(line) for line in lines if line.strip()]
    return {p["mac_address"]: p for p in payloads}


def _received_by_mac(stub: BlueFlowStub) -> dict[str, dict]:
    return {r.body["mac_address"]: r.body for r in stub.received}


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="--network=host smoke is Linux-only")
@pytest.mark.skipif(not _docker_daemon_available(), reason="docker daemon not reachable")
@pytest.mark.skipif(not DEMO_DOCKERFILE.exists(), reason=f"Missing: {DEMO_DOCKERFILE}")
@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ASSETS.exists(), reason=f"Missing: {GOLDEN_ASSETS}")
def test_phase1_demo_image_upserts_against_stub_blueflow() -> None:
    """Full upsert path: 8x201, bodies match golden; re-run yields 8x200."""
    _build_demo_image()

    stub = BlueFlowStub(token=SMOKE_TOKEN)
    port = stub.start()
    try:
        golden_by_mac = _golden_payloads_by_mac()
        assert len(golden_by_mac) == EXPECTED_MAC_COUNT

        first = _run_demo_container(port=port)
        assert first.returncode == 0, (
            f"demo container exited {first.returncode}\n"
            f"stderr:\n{first.stderr.decode(errors='replace')}"
        )
        assert len(stub.received) == EXPECTED_MAC_COUNT, (
            f"Expected {EXPECTED_MAC_COUNT} PUTs, got {len(stub.received)}"
        )
        assert all(r.status == 201 for r in stub.received), (
            "First-write path must return 201 for every MAC; "
            f"statuses: {[r.status for r in stub.received]}"
        )
        assert _received_by_mac(stub) == golden_by_mac, (
            "PUT bodies must match golden_synthetic_philips_assets.jsonl (keyed by mac_address)."
        )

        second = _run_demo_container(port=port)
        assert second.returncode == 0, (
            f"demo container re-run exited {second.returncode}\n"
            f"stderr:\n{second.stderr.decode(errors='replace')}"
        )
        rerun_records = stub.received[EXPECTED_MAC_COUNT:]
        assert len(rerun_records) == EXPECTED_MAC_COUNT, (
            f"Expected {EXPECTED_MAC_COUNT} PUTs on re-run, got {len(rerun_records)}"
        )
        assert all(r.status == 200 for r in rerun_records), (
            "Idempotent re-run must return 200 for every MAC; "
            f"statuses: {[r.status for r in rerun_records]}"
        )
    finally:
        stub.stop()
