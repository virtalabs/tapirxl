"""Unit tests for parser/serialize.to_envelope().

Locks the flat-dict to typed `HostEnvelope` projection across pipelines,
triage, and the closed routing enum.
"""

from __future__ import annotations

import pydantic
import pytest

from tapirxl.parser.envelope_builder import make_empty_envelope
from tapirxl.parser.serialize import to_envelope
from tapirxl.schemas.envelope import HostEnvelope


def _bare_envelope() -> dict:
    return make_empty_envelope("00:09:fb:bd:75:6d", oui_table={})


class TestToEnvelopeBare:
    def test_bare_validates(self) -> None:
        env_dict = _bare_envelope()
        envelope = to_envelope(env_dict)
        assert isinstance(envelope, HostEnvelope)
        assert envelope.host_id == "00:09:fb:bd:75:6d"
        assert envelope.pipeline_1 is None
        assert envelope.pipeline_2 is None
        assert envelope.pipeline_3 is None

    def test_bare_ethernet_block(self) -> None:
        envelope = to_envelope(_bare_envelope())
        assert envelope.ethernet is not None
        assert envelope.ethernet.mac == "00:09:FB:BD:75:6D"


class TestToEnvelopeWsDiscovery:
    def test_ws_discovery_mapping(self) -> None:
        env_dict = _bare_envelope()
        env_dict["pipeline_1"] = {
            "ws_discovery_seen": True,
            "deterministic_label": "Philips IntelliVue MX700/MX800",
            "deterministic_confidence": "HIGH",
        }
        env_dict["ws_uuid"] = "50484248-1234-5678-9abc-def012345678"
        env_dict["ws_vendor_prefix"] = "5048"
        env_dict["ws_series_code"] = "BH"
        env_dict["ws_types"] = ["urn:example:Type1", "urn:example:Type2"]
        env_dict["ws_scopes"] = ["urn:example:scope"]

        envelope = to_envelope(env_dict)
        assert envelope.pipeline_1 is not None
        ws = envelope.pipeline_1.ws_discovery
        assert ws is not None
        assert ws.uuid == "50484248-1234-5678-9abc-def012345678"
        assert ws.vendor_prefix_hex == "5048"
        assert ws.series_code_hex == "BH"
        assert ws.types == ["urn:example:Type1", "urn:example:Type2"]
        assert ws.scopes == ["urn:example:scope"]
        assert ws.deterministic_confidence == "HIGH"


class TestToEnvelopeDicomList:
    def test_dicom_list_mapping(self) -> None:
        env_dict = _bare_envelope()
        env_dict["pipeline_3"] = {
            "dicom_association": [
                {
                    "dicom_association": {
                        "pdu_type_byte": "01",
                        "implementation_class_uid": "1.3.46.670589.30.36.0",
                        "implementation_version_name": "Eleva 4.5",
                        "sop_class_hints": ["1.3.46.->Philips Healthcare"],
                        "philips_image_uid_arc_hits": ["1.2.840.113704."],
                        "dicom_modality": "CT",
                        "dicom_manufacturer": "Philips Healthcare",
                        "dicom_manufacturer_model": "Brilliance iCT",
                        "dicom_software_versions": "Eleva 4.5.1",
                    }
                },
                {
                    "dicom_association": {
                        "pdu_type_byte": "02",
                        "implementation_class_uid": "1.2.840.113619.6.95",
                        "implementation_version_name": "",
                        "sop_class_hints": [],
                        "dicom_modality": "MR",
                    }
                },
            ]
        }

        envelope = to_envelope(env_dict)
        assert envelope.pipeline_3 is not None
        assert len(envelope.pipeline_3.dicom_association) == 2
        first, second = envelope.pipeline_3.dicom_association
        assert first.implementation_class_uid == "1.3.46.670589.30.36.0"
        assert first.tags.manufacturer == "Philips Healthcare"
        assert first.tags.model_name == "Brilliance iCT"
        assert first.tags.modality == "CT"
        assert first.tags.software_versions == ["Eleva 4.5.1"]
        assert first.image_uid_arc_counts == {"1.2.840.113704.": 1}
        assert second.implementation_class_uid == "1.2.840.113619.6.95"
        assert second.tags.modality == "MR"


class TestToEnvelopeTriage:
    def test_consensus_mapping(self) -> None:
        env_dict = _bare_envelope()
        env_dict["triage"]["deterministic_consensus"] = {
            "label": "Philips IntelliVue MX700/MX800",
            "confidence": "HIGH",
        }

        envelope = to_envelope(env_dict)
        assert envelope.triage is not None
        cons = envelope.triage.deterministic_consensus
        assert cons.device_class == "Philips IntelliVue MX700/MX800"
        assert cons.confidence == "HIGH"

    def test_routing_ambiguous_validates(self) -> None:
        env_dict = _bare_envelope()
        env_dict["triage"]["routing"] = "AMBIGUOUS"

        envelope = to_envelope(env_dict)
        assert envelope.triage is not None
        assert envelope.triage.routing == "AMBIGUOUS"

    def test_invalid_routing_rejected(self) -> None:
        env_dict = _bare_envelope()
        env_dict["triage"]["routing"] = "ENQUEUE_FUSION"

        with pytest.raises(pydantic.ValidationError):
            to_envelope(env_dict)


class TestToEnvelopeInternalKeyHandling:
    def test_drops_internal_keys(self) -> None:
        env_dict = _bare_envelope()
        env_dict["_processing_path"] = "SKIP"
        env_dict["_deterministic_preset"] = {"device_class": "X", "confidence": "HIGH"}
        env_dict["_pkt_ts"] = [1.0, 2.0]
        env_dict["_ssh_banners"] = ["SSH-2.0-OpenSSH"]

        envelope = to_envelope(env_dict)
        dumped = envelope.model_dump_json()
        assert "_processing_path" not in dumped
        assert "_deterministic_preset" not in dumped
        assert "_pkt_ts" not in dumped
        assert "_ssh_banners" not in dumped


class TestToEnvelopeRoundTrip:
    def test_round_trip_minimal(self) -> None:
        env_dict = _bare_envelope()
        env_dict["triage"]["routing"] = "STAMP_LOW"
        envelope = to_envelope(env_dict)

        as_json = envelope.model_dump_json()
        roundtripped = HostEnvelope.model_validate_json(as_json)
        assert roundtripped.host_id == envelope.host_id
        assert roundtripped.triage is not None
        assert roundtripped.triage.routing == "STAMP_LOW"
