"""Unit tests for the v1 → v2 HostEnvelope migration.

Covers absence-of-field detection, idempotency, legacy routing remap, and
preservation of unrelated fields. The post-migration dict must validate as
a `HostEnvelope` for the minimum required shape.
"""

from __future__ import annotations

import pytest

from tapirxl.schemas.envelope import SCHEMA_VERSION, HostEnvelope
from tapirxl.schemas.migrations import promote_v1_to_v2


class TestPromoteAddsSchemaVersion:
    def test_absence_of_field_treated_as_v1(self) -> None:
        v1 = {"host_id": "aa:bb:cc:dd:ee:ff"}
        out = promote_v1_to_v2(v1)
        assert out["schema_version"] == 2

    def test_explicit_v1_marker_promoted(self) -> None:
        v1 = {"host_id": "aa:bb:cc:dd:ee:ff", "schema_version": 1}
        out = promote_v1_to_v2(v1)
        assert out["schema_version"] == 2


class TestPromoteIsIdempotent:
    def test_already_v2_returned_unchanged(self) -> None:
        v2 = {"host_id": "aa:bb:cc:dd:ee:ff", "schema_version": 2}
        out = promote_v1_to_v2(v2)
        assert out is v2

    def test_double_promotion_stable(self) -> None:
        v1 = {"host_id": "aa:bb:cc:dd:ee:ff"}
        once = promote_v1_to_v2(v1)
        twice = promote_v1_to_v2(once)
        assert twice == once


class TestLegacyRoutingRemap:
    @pytest.mark.parametrize(
        "legacy",
        ["ENQUEUE_NORMALIZE", "ENQUEUE_FULL", "ENQUEUE_FUSION"],
    )
    def test_legacy_routing_collapses_to_ambiguous(self, legacy: str) -> None:
        v1 = {
            "host_id": "aa:bb:cc:dd:ee:ff",
            "triage": {"signal_count": 1, "routing": legacy},
        }
        out = promote_v1_to_v2(v1)
        assert out["triage"]["routing"] == "AMBIGUOUS"

    def test_v2_routing_passthrough(self) -> None:
        v1 = {
            "host_id": "aa:bb:cc:dd:ee:ff",
            "triage": {"signal_count": 0, "routing": "SKIP"},
        }
        out = promote_v1_to_v2(v1)
        assert out["triage"]["routing"] == "SKIP"

    def test_triage_missing_routing_untouched(self) -> None:
        v1 = {"host_id": "aa:bb:cc:dd:ee:ff", "triage": {"signal_count": 0}}
        out = promote_v1_to_v2(v1)
        assert out["triage"] == {"signal_count": 0}

    def test_triage_none_untouched(self) -> None:
        v1 = {"host_id": "aa:bb:cc:dd:ee:ff", "triage": None}
        out = promote_v1_to_v2(v1)
        assert out["triage"] is None


class TestPromotePreservesOtherFields:
    def test_unrelated_fields_pass_through(self) -> None:
        v1 = {
            "host_id": "aa:bb:cc:dd:ee:ff",
            "oui_vendor": "Philips",
            "ip_observations": ["10.0.0.5", "10.0.0.6"],
            "first_seen": 1.0,
            "last_seen": 2.0,
        }
        out = promote_v1_to_v2(v1)
        assert out["host_id"] == "aa:bb:cc:dd:ee:ff"
        assert out["oui_vendor"] == "Philips"
        assert out["ip_observations"] == ["10.0.0.5", "10.0.0.6"]
        assert out["first_seen"] == 1.0
        assert out["last_seen"] == 2.0

    def test_input_not_mutated_on_remap(self) -> None:
        v1 = {
            "host_id": "aa:bb:cc:dd:ee:ff",
            "triage": {"routing": "ENQUEUE_NORMALIZE"},
        }
        snapshot = {"host_id": "aa:bb:cc:dd:ee:ff", "triage": {"routing": "ENQUEUE_NORMALIZE"}}
        _ = promote_v1_to_v2(v1)
        assert v1 == snapshot, "promote_v1_to_v2 must not mutate its input"


class TestPromotedDictValidates:
    def test_minimum_shape_validates_against_host_envelope(self) -> None:
        v1 = {"host_id": "aa:bb:cc:dd:ee:ff"}
        out = promote_v1_to_v2(v1)
        env = HostEnvelope.model_validate(out)
        assert env.schema_version == SCHEMA_VERSION
        assert env.host_id == "aa:bb:cc:dd:ee:ff"

    def test_remapped_routing_validates(self) -> None:
        v1 = {
            "host_id": "aa:bb:cc:dd:ee:ff",
            "triage": {
                "signal_count": 2,
                "routing": "ENQUEUE_FULL",
            },
        }
        out = promote_v1_to_v2(v1)
        env = HostEnvelope.model_validate(out)
        assert env.triage is not None
        assert env.triage.routing == "AMBIGUOUS"
