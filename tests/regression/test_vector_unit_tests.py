"""Run Vector's built-in unit tests for the translation transform.

Invokes ``vector test`` against ``configs/upload-vector.toml`` plus the
``configs/upload-vector.tests.toml`` file containing the 8 ``[[tests]]``
stanzas (one per record in the inventory golden). Sub-second; validates
the VRL transform without requiring the full pipeline goldens to be in
sync.

Skipped when the ``vector`` binary is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
MAIN_CONFIG = REPO_ROOT / "configs" / "upload-vector.toml"
TESTS_CONFIG = REPO_ROOT / "configs" / "upload-vector.tests.toml"


@pytest.mark.skipif(shutil.which("vector") is None, reason="vector binary not installed")
@pytest.mark.skipif(not MAIN_CONFIG.exists(), reason=f"Missing: {MAIN_CONFIG}")
@pytest.mark.skipif(not TESTS_CONFIG.exists(), reason=f"Missing: {TESTS_CONFIG}")
def test_vector_unit_tests_pass(tmp_path: Path) -> None:
    """All 8 [[tests]] stanzas in upload-vector.tests.toml pass."""
    data_dir = tmp_path / "vector-data"
    data_dir.mkdir()
    proc = subprocess.run(
        [
            "vector",
            "test",
            "--config-toml",
            str(MAIN_CONFIG),
            "--config-toml",
            str(TESTS_CONFIG),
        ],
        capture_output=True,
        check=False,
        cwd=REPO_ROOT,
        timeout=30,
        env={
            # The main config requires these to construct the http sink; the
            # tests don't exercise the sink but the config still needs to
            # parse, so provide stub values. Inherit PATH from the calling
            # environment so Homebrew/apt installs of `vector` resolve.
            **os.environ,
            "BLUEFLOW_URL": "http://localhost:0",
            "BLUEFLOW_TOKEN": "test-token-not-used",
            "TAPIRXL_INVENTORY_FILE": "/var/lib/tapirxl/inventory.jsonl",
            "VECTOR_DATA_DIR": str(data_dir),
        },
    )
    assert proc.returncode == 0, (
        f"`vector test` exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout.decode(errors='replace')}\n"
        f"stderr:\n{proc.stderr.decode(errors='replace')}"
    )
