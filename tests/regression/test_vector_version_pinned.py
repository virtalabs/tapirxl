"""Vector binary version pin guard.

Asserts that the locally installed ``vector`` binary matches the version
pinned in ``packaging/docker/vector/Dockerfile`` (``FROM`` tag), and that
the pin is structurally valid (``MAJOR.MINOR.PATCH``).

Rationale: byte-identical golden equality in ``test_vector_pipeline.py``
is sensitive to Vector's JSON serializer output ordering. Pinning the
binary version is the same discipline as ``pyshark==0.6`` in
``pyproject.toml``.

Skipped when the ``vector`` binary is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
VECTOR_DOCKERFILE = REPO_ROOT / "packaging" / "docker" / "vector" / "Dockerfile"

# Matches e.g. `FROM timberio/vector:0.55.0-debian` and captures `0.55.0`.
_FROM_TAG_RE = re.compile(
    r"^FROM\s+timberio/vector:(?P<version>\d+\.\d+\.\d+)(?:-\w+)?",
    re.MULTILINE,
)

# Matches `vector 0.55.0 (...)` style output of `vector --version`.
_VECTOR_VERSION_RE = re.compile(r"vector\s+(?P<version>\d+\.\d+\.\d+)")


def _pinned_version() -> str:
    text = VECTOR_DOCKERFILE.read_text()
    match = _FROM_TAG_RE.search(text)
    assert match is not None, (
        f"Could not parse pinned Vector version from {VECTOR_DOCKERFILE}.\n"
        "Expected a line like: FROM timberio/vector:MAJOR.MINOR.PATCH-debian"
    )
    return match.group("version")


@pytest.mark.skipif(not VECTOR_DOCKERFILE.exists(), reason=f"Missing: {VECTOR_DOCKERFILE}")
def test_pin_is_well_formed() -> None:
    """Dockerfile pin parses to a MAJOR.MINOR.PATCH tuple."""
    version = _pinned_version()
    parts = version.split(".")
    assert len(parts) == 3, f"Pinned version {version!r} is not MAJOR.MINOR.PATCH"
    assert all(p.isdigit() for p in parts), f"Pinned version {version!r} has non-numeric parts"


@pytest.mark.skipif(shutil.which("vector") is None, reason="vector binary not installed")
@pytest.mark.skipif(not VECTOR_DOCKERFILE.exists(), reason=f"Missing: {VECTOR_DOCKERFILE}")
def test_installed_vector_matches_pin() -> None:
    """Locally installed `vector --version` matches the Dockerfile pin (major.minor)."""
    pinned = _pinned_version()
    proc = subprocess.run(
        ["vector", "--version"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
    match = _VECTOR_VERSION_RE.search(output)
    assert match is not None, f"Could not parse `vector --version` output:\n{output}"
    installed = match.group("version")
    pinned_mm = ".".join(pinned.split(".")[:2])
    installed_mm = ".".join(installed.split(".")[:2])
    assert installed_mm == pinned_mm, (
        f"Vector version drift: installed {installed!r}, "
        f"Dockerfile pin {pinned!r} (major.minor: {installed_mm} != {pinned_mm}).\n"
        "Either upgrade/downgrade your local vector binary or update the "
        "Dockerfile pin (and regenerate goldens) intentionally."
    )
