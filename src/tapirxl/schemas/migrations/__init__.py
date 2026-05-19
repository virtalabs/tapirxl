"""HostEnvelope schema migration helpers.

Consumers archiving older `HostEnvelope` JSONL can promote records to the
current schema version before validating with the typed model. Migrations
are forward-only (stable does not implement reverse migration; X5).
"""

from __future__ import annotations

from tapirxl.schemas.migrations.v1_to_v2 import promote_v1_to_v2

__all__ = ["promote_v1_to_v2"]
