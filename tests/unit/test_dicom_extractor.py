"""Unit tests for DICOM User-Info parsing (0x52 / 0x55 sub-items)."""

from __future__ import annotations

from pathlib import Path

from tapirxl.fixtures.loader import load_signal_manifest
from tapirxl.fixtures.protocols import dicom as dicom_emit
from tapirxl.parser._helpers import _parse_a_assoc_ae_titles, _parse_dicom_user_info


def test_parse_impl_uid_from_a_assoc_rq_pdu() -> None:
    manifest = load_signal_manifest()
    flow = next(f for f in manifest.flows if f.type == "dicom_associate_and_cstore")
    pdu = dicom_emit._build_a_assoc_rq(flow)
    impl_uid, impl_ver = _parse_dicom_user_info(pdu)
    assert impl_uid == "1.3.46.670589.30.36.0"
    assert impl_ver == "PMS_ELEVA_416"


def test_parse_impl_uid_from_a_assoc_ac_pdu() -> None:
    manifest = load_signal_manifest()
    flow = next(f for f in manifest.flows if f.type == "dicom_associate_and_cstore")
    pdu = dicom_emit._build_a_assoc_ac(flow)
    impl_uid, impl_ver = _parse_dicom_user_info(pdu)
    assert impl_uid == "1.3.46.670589.40.12.2.1"
    assert impl_ver == "PMS_ELEVA_CCP12"


def test_parse_sonosite_impl_uid_from_a_assoc_rq_pdu() -> None:
    from tapirxl.fixtures.loader import load_signal_manifest as load_manifest

    manifest = load_manifest(Path("src/tapirxl/fixtures/sonosite_us_scenario.toml"))
    flow = next(f for f in manifest.flows if f.type == "dicom_associate_and_cstore")
    pdu = dicom_emit._build_a_assoc_rq(flow)
    impl_uid, impl_ver = _parse_dicom_user_info(pdu)
    assert impl_uid == "1.2.840.114340.3"
    assert impl_ver == "Tiller_SV1000"


def test_ae_titles_from_philips_a_assoc_rq() -> None:
    manifest = load_signal_manifest()
    flow = next(f for f in manifest.flows if f.type == "dicom_associate_and_cstore")
    pdu = dicom_emit._build_a_assoc_rq(flow)
    calling, called = _parse_a_assoc_ae_titles(pdu)
    assert calling == "CT9999999"
    assert called == "CCPLATFORM"


def test_ae_titles_from_sonosite_a_assoc_rq() -> None:
    from tapirxl.fixtures.loader import load_signal_manifest as load_manifest

    manifest = load_manifest(Path("src/tapirxl/fixtures/sonosite_us_scenario.toml"))
    flow = next(f for f in manifest.flows if f.type == "dicom_associate_and_cstore")
    pdu = dicom_emit._build_a_assoc_rq(flow)
    calling, called = _parse_a_assoc_ae_titles(pdu)
    assert calling == "SONOSITE"
    assert called == "RECEIVER"
