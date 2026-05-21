"""Byte-identical smoke test for the unified ``tapirxl:demo-dev`` image.

Builds (or reuses, via Docker's layer cache) ``tapirxl:demo-dev`` from
``packaging/docker/demo/Dockerfile``, runs it in ``pcap`` mode with
``configs/upload-vector.dryrun.toml`` mounted over the baked-in pcap
config, and asserts the captured stdout is byte-identical to
``tests/regression/golden_synthetic_philips_assets.jsonl``.

This is the unified-image companion to
[`test_vector_pipeline.py`](test_vector_pipeline.py) (which exercises the
same Vector translation outside a container) and
[`test_golden.py`](test_golden.py) (which guards the parser side). All
three feed the same golden; a regression in either layer trips its
dedicated assertion.

Skipped when the ``docker`` binary is unavailable or its daemon is
unreachable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURE_PCAP = REPO_ROOT / "tests" / "fixtures" / "synthetic_philips_demo.pcap"
GOLDEN_ASSETS = REPO_ROOT / "tests" / "regression" / "golden_synthetic_philips_assets.jsonl"
DEMO_DOCKERFILE = REPO_ROOT / "packaging" / "docker" / "demo" / "Dockerfile"
DRYRUN_CONFIG = REPO_ROOT / "configs" / "upload-vector.dryrun.toml"

DEMO_IMAGE_TAG = "tapirxl:demo-dev"


def _docker_daemon_available() -> bool:
    """True iff the `docker` binary can reach a daemon (not just `docker --help`)."""
    if shutil.which("docker") is None:
        return False
    proc = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    return proc.returncode == 0


def _diff_message(actual: bytes, expected: bytes) -> str:
    return (
        f"\nGolden mismatch against {GOLDEN_ASSETS.relative_to(REPO_ROOT)}.\n"
        f"  expected bytes: {len(expected)}\n"
        f"  actual bytes:   {len(actual)}\n"
        "If the diff is intentional (image change), regenerate the assets golden:\n"
        "  just golden-regenerate\n"
        "and review the diff before committing. Otherwise investigate — "
        "this test guards the demo image's BlueFlow wire contract.\n"
    )


@pytest.mark.skipif(not _docker_daemon_available(), reason="docker daemon not reachable")
@pytest.mark.skipif(not DEMO_DOCKERFILE.exists(), reason=f"Missing: {DEMO_DOCKERFILE}")
@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ASSETS.exists(), reason=f"Missing: {GOLDEN_ASSETS}")
@pytest.mark.skipif(not DRYRUN_CONFIG.exists(), reason=f"Missing: {DRYRUN_CONFIG}")
def test_demo_image_byte_identical() -> None:
    """`tapirxl:demo-dev` pcap-mode stdout matches the assets golden, byte-for-byte."""
    build = subprocess.run(
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
    assert build.returncode == 0, build.stderr.decode(errors="replace")

    fixtures_dir = FIXTURE_PCAP.parent.resolve()
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{DRYRUN_CONFIG.resolve()}:/etc/vector/upload-vector.stdin.toml:ro",
            "-v",
            f"{fixtures_dir}:/pcap:ro",
            "-e",
            "TAPIRXL_MODE=pcap",
            "-e",
            f"TAPIRXL_PCAP_PATH=/pcap/{FIXTURE_PCAP.name}",
            "-e",
            "BLUEFLOW_URL=http://localhost:0",
            "-e",
            "BLUEFLOW_TOKEN=test-stub",
            DEMO_IMAGE_TAG,
        ],
        capture_output=True,
        check=True,
        timeout=120,
    )
    actual = run.stdout
    expected = GOLDEN_ASSETS.read_bytes()
    assert actual == expected, _diff_message(actual, expected)


@pytest.mark.skipif(not _docker_daemon_available(), reason="docker daemon not reachable")
@pytest.mark.skipif(not DEMO_DOCKERFILE.exists(), reason=f"Missing: {DEMO_DOCKERFILE}")
def test_demo_image_live_mode_requires_interface() -> None:
    """``TAPIRXL_MODE=live`` requires ``TAPIRXL_INTERFACE``; fails fast without it."""
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "TAPIRXL_MODE=live",
            "-e",
            "BLUEFLOW_URL=http://x",
            "-e",
            "BLUEFLOW_TOKEN=x",
            DEMO_IMAGE_TAG,
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode != 0, (
        f"Expected non-zero exit when TAPIRXL_INTERFACE is missing, got {proc.returncode}. "
        f"stderr: {proc.stderr.decode(errors='replace')!r}"
    )
    assert b"TAPIRXL_INTERFACE" in proc.stderr, (
        f"Expected TAPIRXL_INTERFACE requirement in stderr, got: "
        f"{proc.stderr.decode(errors='replace')!r}"
    )
