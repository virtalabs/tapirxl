"""Load a signal manifest TOML file into a typed :class:`SignalManifest`.

Three-pass resolution (REQ-LOD-002):

1. **Parse** — ``tomllib.load`` produces a raw ``dict``.
2. **Profile merge** — For each asset protocol sub-table and each ``[[flows]]``
   entry that carries a ``*_profile`` key, the referenced profile's fields are
   merged in; the asset's or flow's own explicit keys win (REQ-REF-004).  A
   missing profile name raises :exc:`ManifestValidationError` (REQ-REF-003).
3. **Hex decode** — String values whose key ends in ``_hex`` are decoded to
   ``bytes`` via ``bytes.fromhex()`` (REQ-BYT-002).

The loader is a pure function of the manifest file contents — no env-var
reads, network access, or secondary file I/O (REQ-LOD-003).
"""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tapirxl.fixtures.manifest import SignalManifest

DEFAULT_MANIFEST_PATH = Path(__file__).with_name("signal_manifest.toml")

# Protocol sub-table names that participate in profile merge.
# Mirrors manifest._KNOWN_PROTOCOL_SUBTABLES — kept separate so a future
# schema-known sub-table can opt out of profile merge without loader changes.
_PROFILE_CARRYING_SUBTABLES = frozenset({"dhcp", "wsdiscovery", "tcp_syn", "llmnr_response"})
_PROFILE_KEY_SUFFIX = "_profile"


class ManifestValidationError(Exception):
    """Stable public error type for manifest validation failures.

    Wraps :class:`pydantic.ValidationError` and resolve-phase errors so callers
    only need to catch one exception type.
    """


# ── Pass 2 — profile merge ────────────────────────────────────────────────────


def _merge_profile_into(
    sub_table: dict[str, Any],
    profiles: dict[str, dict[str, Any]],
    context: str,
) -> dict[str, Any]:
    """Return a copy of *sub_table* with profile fields merged in (caller wins).

    Looks for any key ending in ``_profile``; if found, merges the referenced
    profile dict as a base layer before the caller's explicit keys.
    """
    result = dict(sub_table)
    for key in list(sub_table.keys()):
        if not key.endswith(_PROFILE_KEY_SUFFIX):
            continue
        profile_name = sub_table[key]
        if not isinstance(profile_name, str):
            continue
        if profile_name not in profiles:
            raise ManifestValidationError(
                f"{context}: {key}={profile_name!r} references a profile "
                "that does not exist in [profiles] (REQ-REF-003)"
            )
        profile_data = profiles[profile_name]
        # Profile fields are the base layer; caller explicit keys override (REQ-REF-004)
        merged = {k: v for k, v in profile_data.items() if k != "description"}
        merged.update(result)
        result = merged
    return result


def _resolve_profiles(raw: dict[str, Any]) -> dict[str, Any]:
    """Pass 2: resolve *_profile references in asset sub-tables and flows."""
    out = copy.deepcopy(raw)
    profiles: dict[str, dict] = out.get("profiles", {})

    for slug, asset_data in out.get("assets", {}).items():
        if not isinstance(asset_data, dict):
            continue
        for sub_key, sub_val in list(asset_data.items()):
            if isinstance(sub_val, dict) and sub_key in _PROFILE_CARRYING_SUBTABLES:
                asset_data[sub_key] = _merge_profile_into(
                    sub_val,
                    profiles,
                    context=f"asset {slug!r} sub-table {sub_key!r}",
                )

    flows = out.get("flows", [])
    if isinstance(flows, list):
        for i, flow_data in enumerate(flows):
            if not isinstance(flow_data, dict):
                continue
            flows[i] = _merge_profile_into(
                flow_data,
                profiles,
                context=f"flows[{i}]",
            )

    return out


# ── Pass 3 — _hex decode ─────────────────────────────────────────────────────


def _decode_hex_values(obj: Any) -> Any:
    """Recursively decode string values whose key ends in ``_hex`` to bytes."""
    if isinstance(obj, dict):
        return {
            k: (_hex_decode(k, v) if k.endswith("_hex") else _decode_hex_values(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_decode_hex_values(item) for item in obj]
    return obj


def _hex_decode(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ManifestValidationError(
            f"key {key!r} ends in '_hex' but value {value!r} is not valid hex (REQ-BYT-002)"
        ) from exc


# ── Combined resolution ───────────────────────────────────────────────────────


def _resolve_raw_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply passes 2 and 3 to a freshly parsed TOML dict."""
    resolved = _resolve_profiles(raw)
    resolved = _decode_hex_values(resolved)
    return resolved


# ── Public API ────────────────────────────────────────────────────────────────


def load_signal_manifest(path: Path | None = None) -> SignalManifest:
    """Load, resolve, and validate a signal manifest TOML file.

    Parameters
    ----------
    path:
        Filesystem path to the ``.toml`` file.  Defaults to the bundled
        ``signal_manifest.toml`` beside this module (REQ-LOD-001).

    Returns
    -------
    SignalManifest
        Fully resolved, validated manifest object.

    Raises
    ------
    ManifestValidationError
        On any schema, reference, or validation failure.
    FileNotFoundError
        If *path* is given but does not exist.
    """
    resolved_path = path or DEFAULT_MANIFEST_PATH
    with resolved_path.open("rb") as fh:
        raw: dict[str, Any] = tomllib.load(fh)

    try:
        resolved = _resolve_raw_manifest(raw)
        return SignalManifest.model_validate(resolved)
    except ManifestValidationError:
        raise
    except ValidationError as exc:
        raise ManifestValidationError(str(exc)) from exc


# Convenience alias
load_manifest = load_signal_manifest
