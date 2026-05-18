"""Unit tests for parser/triage.route_host() — locks spec §6.1 ordering."""

from __future__ import annotations

from tapirxl.parser.envelope_builder import make_empty_envelope
from tapirxl.parser.triage import route_host


def _bare_envelope() -> dict:
    """Empty envelope with all default keys triage relies on."""
    env = make_empty_envelope("00:09:fb:bd:75:6d", oui_table={})
    return env


class TestRouteHostSpecOrdering:
    """Locks the §6.1 first-match-wins ordering against future regressions."""

    def test_signal_count_zero_no_expert_flags_routes_skip(self) -> None:
        env = _bare_envelope()
        env["signal_count"] = 0
        env["expert_flags"] = []

        route_host(env)

        assert env["triage"]["routing"] == "SKIP"

    def test_contradiction_codes_force_fusion_before_deterministic(self) -> None:
        """Defensive deviation from spec: contradictions early-exit to fusion."""
        env = _bare_envelope()
        env["signal_count"] = 3
        env["triage"]["contradiction_codes"] = ["C1"]
        env["pipeline_1"] = {
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }
        env["pipeline_3"] = {
            "deterministic_label": "Philips modality / DICOM-speaking device",
            "deterministic_confidence": "HIGH",
        }

        route_host(env)

        assert env["triage"]["routing"] == "ENQUEUE_FUSION"

    def test_single_signal_no_floor_triggers_routes_stamp_low(self) -> None:
        """STAMP_LOW must beat DETERMINISTIC_FINAL when signal_count == 1."""
        env = _bare_envelope()
        env["signal_count"] = 1
        env["floor_triggers"] = []
        env["pipeline_1"] = {
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }

        route_host(env)

        assert env["triage"]["routing"] == "STAMP_LOW"

    def test_high_consensus_with_ambiguous_fields_routes_normalize(self) -> None:
        """Regression: HIGH consensus must NOT short-circuit when amb fields exist.

        This is the routing bug fixed in this commit — previously HIGH consensus
        sent the host to DETERMINISTIC_FINAL even with unresolved WS-D types,
        skipping normalization entirely.
        """
        env = _bare_envelope()
        env["signal_count"] = 3
        env["ws_types"] = ["urn:vendor-unknown:something-ambiguous:1"]
        env["pipeline_1"] = {
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }
        env["pipeline_3"] = {
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }

        route_host(env)

        assert env["triage"]["routing"] in (
            "ENQUEUE_NORMALIZE",
            "ENQUEUE_FULL",
        )
        assert env["triage"]["routing"] != "DETERMINISTIC_FINAL"

    def test_high_consensus_no_ambiguous_routes_deterministic_final(self) -> None:
        """The positive case: HIGH consensus + no ambiguity → DETERMINISTIC_FINAL."""
        env = _bare_envelope()
        env["signal_count"] = 3
        env["ws_types"] = []
        env["mdns_txt_raw"] = []
        env["pipeline_1"] = {
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }
        env["pipeline_3"] = {
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }

        route_host(env)

        assert env["triage"]["routing"] == "DETERMINISTIC_FINAL"
        assert env["_deterministic_preset"]["confidence"] == "HIGH"
