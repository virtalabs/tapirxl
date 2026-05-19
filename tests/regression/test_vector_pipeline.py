"""Golden regression test for the Vector translation pipeline.

Pipes the existing InventoryRecord golden through the dry-run Vector
config and asserts byte-identical output against the expected
AssetUpsertPayload golden. Mirrors the discipline of
``tests/regression/test_golden.py`` from PR #6.

Skipped when the ``vector`` binary is unavailable. Install via
``brew install vectordotdev/brew/vector`` or the apt repo. CI installs
the pinned version (see ``packaging/docker/vector/Dockerfile`` for the
canonical pin and ``test_vector_version_pinned.py`` for the enforcement).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
GOLDEN_INVENTORY = REPO_ROOT / "tests" / "regression" / "golden_synthetic_philips_inventory.jsonl"
GOLDEN_ASSETS = REPO_ROOT / "tests" / "regression" / "golden_synthetic_philips_assets.jsonl"
DRYRUN_CONFIG = REPO_ROOT / "configs" / "upload-vector.dryrun.toml"


def _diff_message(actual: bytes, expected: bytes) -> str:
    return (
        f"\nGolden mismatch against {GOLDEN_ASSETS.relative_to(REPO_ROOT)}.\n"
        f"  expected bytes: {len(expected)}\n"
        f"  actual bytes:   {len(actual)}\n"
        "If the diff is intentional (translation change), regenerate with:\n"
        "  just golden-regenerate\n"
        "and review the diff before committing. Otherwise investigate — "
        "this test guards the BlueFlow wire contract.\n"
    )


@pytest.mark.skipif(shutil.which("vector") is None, reason="vector binary not installed")
@pytest.mark.skipif(not GOLDEN_INVENTORY.exists(), reason=f"Missing: {GOLDEN_INVENTORY}")
@pytest.mark.skipif(not GOLDEN_ASSETS.exists(), reason=f"Missing: {GOLDEN_ASSETS}")
@pytest.mark.skipif(not DRYRUN_CONFIG.exists(), reason=f"Missing: {DRYRUN_CONFIG}")
def test_vector_pipeline_byte_identical() -> None:
    """Vector translation produces byte-identical AssetUpsertPayload JSONL."""
    proc = subprocess.run(
        ["vector", "--quiet", "--config-toml", str(DRYRUN_CONFIG)],
        input=GOLDEN_INVENTORY.read_bytes(),
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    actual = proc.stdout
    expected = GOLDEN_ASSETS.read_bytes()
    assert actual == expected, _diff_message(actual, expected)
