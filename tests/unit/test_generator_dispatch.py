"""Dispatch-table parity tests for the manifest-driven PCAP generator."""

from __future__ import annotations

from typing import get_args

from tapirxl.fixtures.generator import FLOW_HANDLERS, SOLO_HANDLERS
from tapirxl.fixtures.manifest import (
    Asset,
    FlowArpExchange,
    FlowDicomAssocAndCStore,
    FlowLlmnrQuery,
    FlowSmb2Negotiate,
    FlowSmb2NtlmsspSetup,
    FlowTcpSyn,
    FlowTlsClientHello,
)

# tcp_syn is validated on assets but dispatched only via [[flows]] entries.
_FLOW_ONLY_EMITS = frozenset({"tcp_syn"})

_FLOW_CLASSES = (
    FlowArpExchange,
    FlowDicomAssocAndCStore,
    FlowSmb2Negotiate,
    FlowSmb2NtlmsspSetup,
    FlowTlsClientHello,
    FlowLlmnrQuery,
    FlowTcpSyn,
)


def _literal_values(annotation: object) -> set[str]:
    args = get_args(annotation)
    if not args:
        return set()
    if get_args(args[0]):
        return set(get_args(args[0]))
    return set(args)


def test_flow_handlers_cover_all_flow_types() -> None:
    flow_types = {get_args(cls.model_fields["type"].annotation)[0] for cls in _FLOW_CLASSES}
    assert flow_types == set(FLOW_HANDLERS)


def test_solo_handlers_cover_emits() -> None:
    emits_ann = Asset.model_fields["emits"].annotation
    emit_values = _literal_values(emits_ann)
    assert emit_values - _FLOW_ONLY_EMITS == set(SOLO_HANDLERS)
