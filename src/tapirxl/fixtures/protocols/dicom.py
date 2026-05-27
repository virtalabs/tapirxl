"""DICOM A-ASSOCIATE + C-STORE emitter for multi-host flows."""

from __future__ import annotations

from collections.abc import Iterable
from io import BytesIO
from typing import TYPE_CHECKING

from tapirxl.fixtures.protocols._helpers import (
    TcpState,
    tcp_fin_teardown,
    tcp_psh_exchange,
    tcp_three_way_hs,
)

if TYPE_CHECKING:
    from tapirxl.fixtures.manifest import FlowDicomAssocAndCStore, SignalManifest

_DICOM_APP_CONTEXT = "1.2.840.10008.3.1.1.1"


def emit_flow(
    flow: FlowDicomAssocAndCStore, manifest: SignalManifest
) -> Iterable[tuple[float, object]]:
    client = manifest.assets[flow.client]
    server = manifest.assets[flow.server]

    a_rq = _build_a_assoc_rq(flow)
    a_ac = _build_a_assoc_ac(flow)
    c_store_rq = _dimse_c_store_rq(flow)
    c_store_rsp = _dimse_c_store_rsp(flow)

    a_rq_pdus = [a_rq]
    a_ac_pdus = [a_ac]
    c_rq_pdus = _pdata_pdus(c_store_rq, cid=1, max_pdu=flow.max_pdu)
    c_rsp_pdus = _pdata_pdus(c_store_rsp, cid=1, max_pdu=flow.max_pdu)

    init = TcpState(
        cli_seq=0x1A001B00,
        srv_seq=0x2F002C00,
        client_mac=client.mac,
        server_mac=server.mac,
        client_ip=client.ip,
        server_ip=server.ip,
        client_port=flow.client_port,
        server_port=flow.server_port,
        client_ttl=64,
        server_ttl=64,
    )
    pkts: list[object] = []
    hs, tcpst = tcp_three_way_hs(init, flow.client_port, flow.server_port)
    pkts.extend(hs)

    for pdu in a_rq_pdus:
        seg, tcpst = tcp_psh_exchange(sender="client", tcpst=tcpst, pdu=pdu)
        pkts.extend(seg)
    for pdu in a_ac_pdus:
        seg, tcpst = tcp_psh_exchange(sender="server", tcpst=tcpst, pdu=pdu)
        pkts.extend(seg)
    for pdu in c_rq_pdus:
        seg, tcpst = tcp_psh_exchange(sender="client", tcpst=tcpst, pdu=pdu)
        pkts.extend(seg)
    for pdu in c_rsp_pdus:
        seg, tcpst = tcp_psh_exchange(sender="server", tcpst=tcpst, pdu=pdu)
        pkts.extend(seg)

    pkts.extend(tcp_fin_teardown(tcpst))

    for pkt in pkts:
        yield (flow.emit_at_s, pkt)


def _build_a_assoc_rq(flow: FlowDicomAssocAndCStore) -> bytes:
    try:
        from pydicom.uid import UID as _PUID
        from pynetdicom.pdu import A_ASSOCIATE_RQ
        from pynetdicom.pdu_primitives import A_ASSOCIATE as _AA
        from pynetdicom.pdu_primitives import ImplementationVersionNameNotification as _IVN
        from pynetdicom.presentation import PresentationContext
    except ImportError as exc:
        raise SystemExit("pip install pydicom pynetdicom") from exc

    cx = PresentationContext()
    cx.context_id = 1
    cx.abstract_syntax = _PUID(flow.abstract_syntax)
    cx.transfer_syntax = [_PUID(flow.transfer_syntax)]

    assoc = _AA()
    assoc.application_context_name = _PUID(_DICOM_APP_CONTEXT)
    assoc.calling_ae_title = flow.calling_ae
    assoc.called_ae_title = flow.called_ae
    assoc.presentation_context_definition_list = [cx]
    assoc.maximum_length_received = flow.max_pdu
    assoc.implementation_class_uid = _PUID(flow.client_impl_class_uid)
    ver = _IVN()
    ver.implementation_version_name = flow.client_impl_version
    assoc.user_information.append(ver)
    return bytes(A_ASSOCIATE_RQ(assoc).encode())


def _build_a_assoc_ac(flow: FlowDicomAssocAndCStore) -> bytes:
    try:
        from pydicom.uid import UID as _PUID
        from pynetdicom.pdu import A_ASSOCIATE_AC
        from pynetdicom.pdu_primitives import A_ASSOCIATE as _AA
        from pynetdicom.pdu_primitives import ImplementationVersionNameNotification as _IVN
        from pynetdicom.presentation import PresentationContext
    except ImportError as exc:
        raise SystemExit("pip install pydicom pynetdicom") from exc

    cx = PresentationContext()
    cx.context_id = 1
    cx.abstract_syntax = _PUID(flow.abstract_syntax)
    cx.transfer_syntax = [_PUID(flow.transfer_syntax)]
    cx.result = 0

    assoc = _AA()
    assoc.result = 0
    assoc.application_context_name = _PUID(_DICOM_APP_CONTEXT)
    assoc.calling_ae_title = flow.called_ae  # note: AC swaps AE titles
    assoc.called_ae_title = flow.calling_ae
    assoc.presentation_context_definition_results_list = [cx]
    assoc.maximum_length_received = flow.max_pdu
    assoc.implementation_class_uid = _PUID(flow.server_impl_class_uid)
    ver = _IVN()
    ver.implementation_version_name = flow.server_impl_version
    assoc.user_information.append(ver)
    return bytes(A_ASSOCIATE_AC(assoc).encode())


def _dimse_c_store_rq(flow: FlowDicomAssocAndCStore):

    try:
        from pydicom.dataset import Dataset
        from pydicom.uid import UID as _PUID
        from pynetdicom.dimse_messages import C_STORE_RQ
        from pynetdicom.dimse_primitives import C_STORE
        from pynetdicom.dsutils import encode as ds_encode
    except ImportError as exc:
        raise SystemExit("pip install pydicom pynetdicom") from exc

    ds = Dataset()
    ds.PatientName = flow.dataset_patient_name
    ds.Modality = flow.dataset_modality
    ds.Manufacturer = flow.dataset_manufacturer
    ds.ManufacturerModelName = flow.dataset_model
    ds.SoftwareVersions = flow.dataset_software_versions

    prim = C_STORE()
    prim.MessageID = flow.message_id
    prim.AffectedSOPClassUID = _PUID(flow.abstract_syntax)
    prim.AffectedSOPInstanceUID = _PUID(flow.sop_instance_uid)
    blob = ds_encode(ds, False, True)
    prim.DataSet = BytesIO(blob or b"")

    msg = C_STORE_RQ()
    msg.primitive_to_message(prim)
    return msg


def _dimse_c_store_rsp(flow: FlowDicomAssocAndCStore):
    try:
        from pydicom.uid import UID as _PUID
        from pynetdicom.dimse_messages import C_STORE_RSP
        from pynetdicom.dimse_primitives import C_STORE
    except ImportError as exc:
        raise SystemExit("pip install pydicom pynetdicom") from exc

    prim = C_STORE()
    prim.MessageIDBeingRespondedTo = flow.message_id
    prim.Status = 0x0000
    prim.AffectedSOPClassUID = _PUID(flow.abstract_syntax)
    prim.AffectedSOPInstanceUID = _PUID(flow.sop_instance_uid)
    rsp = C_STORE_RSP()
    rsp.primitive_to_message(prim)
    return rsp


def _pdata_pdus(dimse_msg, *, cid: int = 1, max_pdu: int) -> list[bytes]:
    try:
        from pynetdicom.pdu import P_DATA_TF
    except ImportError as exc:
        raise SystemExit("pip install pynetdicom") from exc

    return [bytes(P_DATA_TF(p).encode()) for p in dimse_msg.encode_msg(cid, max_pdu)]
