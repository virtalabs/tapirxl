"""Phase 2 integration smoke: live ``tapirxl:demo-dev`` → Vector → stub BlueFlow.

Replays the synthetic fixture onto ``lo`` while the demo image listens in
``TAPIRXL_MODE=live``. Linux + Docker + tcpreplay only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
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
CONTAINER_NAME = "tapirxl-live-smoke-test"
LISTENER_READY = "Live capture ready on lo"
POLL_TIMEOUT_SECS = 90.0
LISTENER_READY_TIMEOUT_SECS = 120.0


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


def _tcpreplay_available() -> bool:
    return shutil.which("tcpreplay") is not None


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


def _golden_payloads_by_mac() -> dict[str, dict]:
    lines = GOLDEN_ASSETS.read_text(encoding="utf-8").splitlines()
    payloads = [json.loads(line) for line in lines if line.strip()]
    return {p["mac_address"]: p for p in payloads}


def _container_logs() -> str:
    proc = subprocess.run(
        ["docker", "logs", CONTAINER_NAME],
        capture_output=True,
        check=False,
        timeout=30,
    )
    stdout = proc.stdout.decode(errors="replace")
    stderr = proc.stderr.decode(errors="replace")
    return f"{stdout}{stderr}".strip()


def _container_is_running() -> bool:
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
        capture_output=True,
        check=False,
        timeout=10,
    )
    return proc.returncode == 0 and proc.stdout.decode().strip() == "true"


def _stop_container() -> None:
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER_NAME],
        capture_output=True,
        check=False,
        timeout=30,
    )


def _start_live_container(*, port: int) -> None:
    _stop_container()
    proc = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            CONTAINER_NAME,
            "--network=host",
            "--cap-add=NET_ADMIN",
            "--cap-add=NET_RAW",
            "-e",
            "TAPIRXL_MODE=live",
            "-e",
            "TAPIRXL_INTERFACE=lo",
            "-e",
            "TAPIRXL_INITIAL_EMIT_SECS=0.5",
            "-e",
            "TAPIRXL_QUIESCENCE_SECS=2",
            "-e",
            f"BLUEFLOW_URL=http://127.0.0.1:{port}",
            "-e",
            f"BLUEFLOW_TOKEN={SMOKE_TOKEN}",
            DEMO_IMAGE_TAG,
        ],
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")


def _wait_for_listener_ready() -> None:
    deadline = time.monotonic() + LISTENER_READY_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if not _container_is_running():
            raise AssertionError(
                f"Demo container exited before live capture was ready.\n{_container_logs()}"
            )
        if LISTENER_READY in _container_logs():
            return
        time.sleep(0.5)
    raise AssertionError(
        f"Timed out waiting for live capture on lo after {LISTENER_READY_TIMEOUT_SECS}s.\n"
        f"{_container_logs()}"
    )


def _replay_pcap(*, loops: int = 20) -> None:
    """Replay the fixture onto ``lo`` at top speed (timestamps ignored).

    tcpreplay needs CAP_NET_RAW on the host. CI runners and most dev machines
    are unprivileged; passwordless ``sudo`` (GHA ubuntu-latest) satisfies that.

    ``pyshark.LiveCapture(...)`` is a lazy constructor — the actual ``tshark``
    subprocess does not spawn until ``sniff_continuously()`` starts iterating,
    which can lag the "Live capture ready" banner by hundreds of ms. Looping
    over a multi-second window with ``--loopdelay-ms`` ensures tshark has at
    least one window where it is genuinely capturing while traffic is flowing.

    ``--preload-pcap`` keeps the fixture in RAM so per-loop overhead is tiny.
    """
    base = [
        "tcpreplay",
        "--intf1=lo",
        "--quiet",
        "--topspeed",
        "--preload-pcap",
        f"--loop={loops}",
        "--loopdelay-ms=200",
        str(FIXTURE_PCAP),
    ]
    if os.geteuid() != 0 and shutil.which("sudo") is not None:
        cmd = ["sudo", "-n", *base]
    else:
        cmd = base
    proc = subprocess.run(
        cmd,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")


def _wait_for_puts(stub: BlueFlowStub, *, count: int) -> None:
    deadline = time.monotonic() + POLL_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if len(stub.received) >= count:
            return
        time.sleep(0.5)
    raise AssertionError(
        f"Timed out waiting for {count} PUTs; got {len(stub.received)} after "
        f"{POLL_TIMEOUT_SECS}s.\nContainer logs:\n{_container_logs()}"
    )


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="live smoke requires Linux host networking")
@pytest.mark.skipif(not _docker_daemon_available(), reason="docker daemon not reachable")
@pytest.mark.skipif(not _tcpreplay_available(), reason="tcpreplay not installed")
@pytest.mark.skipif(not DEMO_DOCKERFILE.exists(), reason=f"Missing: {DEMO_DOCKERFILE}")
@pytest.mark.skipif(not FIXTURE_PCAP.exists(), reason=f"Missing: {FIXTURE_PCAP}")
@pytest.mark.skipif(not GOLDEN_ASSETS.exists(), reason=f"Missing: {GOLDEN_ASSETS}")
def test_phase2_live_demo_image_upserts_against_stub_blueflow() -> None:
    """Live replay on lo → 8x201 with bodies matching the assets golden."""
    _build_demo_image()
    golden_by_mac = _golden_payloads_by_mac()
    assert len(golden_by_mac) == EXPECTED_MAC_COUNT

    stub = BlueFlowStub(token=SMOKE_TOKEN)
    port = stub.start()
    try:
        _start_live_container(port=port)
        _wait_for_listener_ready()
        # Give pyshark a beat to actually spawn tshark/dumpcap before we start
        # replaying. The "Live capture ready" banner only confirms that the
        # Python LiveCapture wrapper was constructed, not that any subprocess
        # is yet bound to lo.
        time.sleep(3.0)
        _replay_pcap()
        _wait_for_puts(stub, count=EXPECTED_MAC_COUNT)

        received = {r.body["mac_address"]: r.body for r in stub.received}
        assert len(received) == EXPECTED_MAC_COUNT
        assert all(r.status == 201 for r in stub.received[:EXPECTED_MAC_COUNT])
        assert received == golden_by_mac
    finally:
        stub.stop()
        _stop_container()
