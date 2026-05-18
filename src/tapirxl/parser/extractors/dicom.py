from __future__ import annotations

from tapirxl.parser._helpers import (
    _base_record,
    _dicom_tag_value_explicit_vr_le,
    _safe,
    _slice_ip_tcp_payload,
)
from tapirxl.parser.tables import DICOM_IMPL_UID_ARCS, DICOM_PHILIPS_IMAGE_UID_ARC


def handle(packet, oui_table: dict) -> dict | None:
    ports = []
    if hasattr(packet, "tcp"):
        ports.extend([str(_safe(packet.tcp, "srcport")), str(_safe(packet.tcp, "dstport"))])
    if not any(p in {"104", "2104", "2762"} for p in ports if str(p).isdigit()):
        return None

    pdu_bytes = _slice_ip_tcp_payload(packet)
    pdu_type = pdu_bytes[0:1].hex() if pdu_bytes else ""
    sop_classes = []
    assoc_info = {"pdu_type_byte": pdu_type}

    impl_uid = getattr(packet.dicom, "tag_2052_uid", "") if hasattr(packet, "dicom") else ""
    impl_ver = getattr(packet.dicom, "tag_2055_pn", "") if hasattr(packet, "dicom") else ""

    philips_arc_hit = []
    pb = pdu_bytes.lower()
    if DICOM_PHILIPS_IMAGE_UID_ARC.encode("ascii").lower() in pb:
        philips_arc_hit.append(DICOM_PHILIPS_IMAGE_UID_ARC)

    for arc in DICOM_IMPL_UID_ARCS:
        if arc.encode().lower() in pb:
            sop_classes.append(f"{arc}->{DICOM_IMPL_UID_ARCS[arc]}")

    modality = _dicom_tag_value_explicit_vr_le(pdu_bytes, 0x0008, 0x0060, b"CS")
    manufacturer = _dicom_tag_value_explicit_vr_le(pdu_bytes, 0x0008, 0x0070, b"LO")
    model_name = _dicom_tag_value_explicit_vr_le(pdu_bytes, 0x0008, 0x1090, b"LO")
    sw_versions = _dicom_tag_value_explicit_vr_le(pdu_bytes, 0x0018, 0x1020, b"LO")

    rec = _base_record(packet, oui_table, "DICOM")
    if not rec:
        return None
    assoc_info.update(
        {
            "implementation_class_uid": str(impl_uid) if impl_uid else "",
            "implementation_version_name": str(impl_ver) if impl_ver else "",
            "sop_class_hints": sop_classes,
            "philips_image_uid_arc_hits": philips_arc_hit,
            "dicom_modality": modality,
            "dicom_manufacturer": manufacturer,
            "dicom_manufacturer_model": model_name,
            "dicom_software_versions": sw_versions,
        }
    )
    rec["raw_fields"] = {"dicom_association": assoc_info}
    return rec
