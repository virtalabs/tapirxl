"""Compose-fragment smoke test.

Validates ``packaging/docker/compose.tapirxl.yaml`` via ``docker compose
config -q``: catches YAML syntax errors, env-var interpolation problems,
and missing referenced Dockerfiles before the demo PR consumes the
fragment via ``include:``.

Skipped when the ``docker`` binary is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
COMPOSE_FRAGMENT = REPO_ROOT / "packaging" / "docker" / "compose.tapirxl.yaml"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker binary not installed")
@pytest.mark.skipif(not COMPOSE_FRAGMENT.exists(), reason=f"Missing: {COMPOSE_FRAGMENT}")
def test_compose_fragment_is_valid() -> None:
    """`docker compose config` parses the fragment with no errors."""
    proc = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FRAGMENT), "config", "-q"],
        capture_output=True,
        check=False,
        cwd=REPO_ROOT,
        timeout=30,
        env={
            # `BLUEFLOW_TOKEN:?` requires a value; provide a placeholder so
            # interpolation succeeds. `config -q` does not open sockets,
            # so the value never reaches a network. Inherit PATH so
            # Homebrew/apt installs of `docker` resolve.
            **os.environ,
            "BLUEFLOW_TOKEN": "test-token-not-used",
        },
    )
    assert proc.returncode == 0, (
        f"`docker compose config` exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout.decode(errors='replace')}\n"
        f"stderr:\n{proc.stderr.decode(errors='replace')}"
    )
