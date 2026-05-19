"""Promote v1-shaped HostEnvelope dicts to v2.

v1 is the pre-`schema_version` shape: absence of the ``schema_version`` key
is the marker. v2 adds ``schema_version: int = 2`` and closes the triage
routing enum to ``{SKIP, STAMP_LOW, DETERMINISTIC_FINAL, AMBIGUOUS}``.

Legacy v1 dicts may carry agent-tier routing codes
(``ENQUEUE_NORMALIZE``, ``ENQUEUE_FULL``, ``ENQUEUE_FUSION``) that no
longer exist in v2; this module collapses them into ``AMBIGUOUS`` so the
record validates against the current Pydantic model.
"""

from __future__ import annotations

from typing import Any

_LEGACY_ROUTING_TO_AMBIGUOUS: frozenset[str] = frozenset(
    {"ENQUEUE_NORMALIZE", "ENQUEUE_FULL", "ENQUEUE_FUSION"}
)


def promote_v1_to_v2(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a v2-shaped envelope dict.

    Idempotent: returns the input unchanged when ``schema_version`` is
    already 2. Preserves all other fields verbatim.
    """
    if raw.get("schema_version") == 2:
        return raw

    out = dict(raw)
    out["schema_version"] = 2

    triage = out.get("triage")
    if isinstance(triage, dict):
        routing = triage.get("routing")
        if routing in _LEGACY_ROUTING_TO_AMBIGUOUS:
            new_triage = dict(triage)
            new_triage["routing"] = "AMBIGUOUS"
            out["triage"] = new_triage

    return out
