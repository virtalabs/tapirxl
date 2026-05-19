"""Compat test: dependency and import discipline guards.

Two complementary mechanisms in one file:

**(a) Project-dependency guard** (G11 per ``tapirxl_domain_split.md`` §11).
Parses ``pyproject.toml``'s ``[project] dependencies`` and asserts the
forbidden set is absent. The forbidden set tracks every dependency that
historically belonged to the agent/LM tier and must never reappear on
``main`` (D8 — parser is LM-free).

**(b) LM-free package import guard** (v0.2 FR §11 item 5).
AST-walks every ``*.py`` file under ``src/tapirxl/{parser,core,schemas,
fixtures}`` and asserts no ``import``/``from`` statement names a dependency
reserved for the uploader tier (``httpx``, ``tenacity``, ``keyring``).
Trivially passes today (none of those packages are installed); becomes the
active guard the moment the ``feat/uploader`` work adds them to
``[project] dependencies``.

Both lists are intentionally defined as constants at the top of this module
so the test doubles as living documentation of the LM-free + read-only
invariants.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
SRC_ROOT = REPO_ROOT / "src" / "tapirxl"

# Dependencies that must never appear in [project] dependencies on `main`.
# Each entry is the PEP 508 distribution name (case-insensitive match).
FORBIDDEN_TOP_LEVEL_DEPS: frozenset[str] = frozenset(
    {
        "dspy-ai",
        "dspy",
        "ollama",
        "jinja2",
        "openai",
        "langchain",
        "anthropic",
    }
)

# Modules that the uploader (feat/uploader, not yet landed) will import,
# and which must NEVER be imported from the LM-free packages below. The
# guard is symmetric: parser/core/schemas/fixtures stay socket-free and
# retry-policy-free, even after the uploader ships.
UPLOADER_ONLY_MODULES: frozenset[str] = frozenset({"httpx", "tenacity", "keyring"})

# Packages bound by the LM-free + read-only invariants (D4, D8).
LM_FREE_PACKAGES: tuple[str, ...] = ("parser", "core", "schemas", "fixtures")


def _normalize_dist_name(spec: str) -> str:
    """Extract the distribution name from a PEP 508 spec like 'pkg>=1.0'."""
    name = spec.split(";", 1)[0].strip()
    for sep in ("==", ">=", "<=", "~=", ">", "<", "!=", "["):
        if sep in name:
            name = name.split(sep, 1)[0]
    return name.strip().lower()


def _imported_top_level(node: ast.AST) -> set[str]:
    """Return the top-level package names imported by an `import` or `from` node."""
    names: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.add(alias.name.split(".", 1)[0])
    elif isinstance(node, ast.ImportFrom):
        if node.module and node.level == 0:
            names.add(node.module.split(".", 1)[0])
    return names


@pytest.fixture(scope="module")
def project_dependencies() -> set[str]:
    if not PYPROJECT.exists():
        pytest.skip(f"{PYPROJECT} missing")
    data = tomllib.loads(PYPROJECT.read_text())
    raw_deps = data.get("project", {}).get("dependencies", [])
    return {_normalize_dist_name(d) for d in raw_deps}


def test_forbidden_top_level_deps_absent(project_dependencies: set[str]) -> None:
    """No LM-tier package may appear in [project] dependencies on `main`."""
    found = project_dependencies & FORBIDDEN_TOP_LEVEL_DEPS
    assert not found, (
        f"Forbidden runtime dependencies found in pyproject.toml: {sorted(found)}. "
        "These belong to the agent/LM tier (experimental/agent only); their presence "
        "violates D8 (parser is LM-free)."
    )


@pytest.mark.parametrize("package", LM_FREE_PACKAGES)
def test_uploader_modules_not_imported_in_lm_free_packages(package: str) -> None:
    """``parser``/``core``/``schemas``/``fixtures`` must not import uploader-only modules.

    Walks every ``*.py`` file under the package, AST-parses imports, and
    fails listing every offending file:line:module.
    """
    pkg_root = SRC_ROOT / package
    if not pkg_root.exists():
        pytest.skip(f"{pkg_root} missing")

    offenders: list[str] = []
    for py_file in pkg_root.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except SyntaxError as exc:
            pytest.fail(f"Could not AST-parse {py_file}: {exc}")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Import | ast.ImportFrom):
                continue
            imported = _imported_top_level(node)
            forbidden = imported & UPLOADER_ONLY_MODULES
            if forbidden:
                rel = py_file.relative_to(REPO_ROOT)
                line = getattr(node, "lineno", 0)
                offenders.append(f"  {rel}:{line} imports {sorted(forbidden)}")

    assert not offenders, (
        f"Uploader-only modules imported inside tapirxl/{package}/ "
        "(v0.2 FR §11 item 5):\n" + "\n".join(offenders)
    )
