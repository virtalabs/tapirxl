"""Compat test: Pydantic `InventoryRecord` ↔ hand-authored JSON Schema.

Per G8, the hand-authored
[`schemas/inventory_record.schema.json`](../../schemas/inventory_record.schema.json)
and the Pydantic model
[`src/tapirxl/schemas/inventory.py`](../../src/tapirxl/schemas/inventory.py)
must agree on:

- the set of property names,
- the `required` set,
- the enum members of `vendor`, `product`, `device_class`, and `confidence`.

Pydantic is the canonical source for client-side validation (v0.2 FR §4.2);
the JSON Schema is the wire spec for non-Python consumers. This test is the
guard against silent drift between the two — one assertion per concern so
the failure message names the drifted field.

The two representations encode "nullable enum" differently — JSON Schema
puts ``null`` in the enum list (``{"enum": [null, "HIGH", ...]}``); Pydantic
generates ``anyOf`` (``[{"enum": ["HIGH", ...], "type": "string"}, {"type":
"null"}]``). The helpers below normalise both to a comparable ``frozenset``
of non-null members.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tapirxl.schemas.inventory import InventoryRecord

SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "inventory_record.schema.json"

_ENUM_FIELDS: tuple[str, ...] = ("vendor", "product", "device_class", "confidence")


def _jsonschema_enum(prop: dict) -> frozenset[str]:
    """Extract non-null enum members from the hand-authored JSON Schema shape."""
    values = prop.get("enum")
    if values is None:
        return frozenset()
    return frozenset(v for v in values if v is not None)


def _pydantic_enum(prop: dict) -> frozenset[str]:
    """Extract non-null enum members from the Pydantic-generated shape.

    Pydantic emits ``{"anyOf": [{"enum": [...], "type": "string"}, {"type": "null"}]}``
    for nullable Literal types; bare ``Literal`` fields produce a top-level
    ``enum`` key. Both shapes are handled here.
    """
    if "enum" in prop:
        return frozenset(prop["enum"])
    any_of = prop.get("anyOf") or []
    for branch in any_of:
        if branch.get("type") == "string" and "enum" in branch:
            return frozenset(branch["enum"])
    return frozenset()


@pytest.fixture(scope="module")
def jsonschema() -> dict:
    if not SCHEMA_PATH.exists():
        pytest.skip(f"JSON Schema not found at {SCHEMA_PATH}")
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def pydanticschema() -> dict:
    return InventoryRecord.model_json_schema()


def test_property_names_match(jsonschema: dict, pydanticschema: dict) -> None:
    js_props = set(jsonschema["properties"].keys())
    py_props = set(pydanticschema["properties"].keys())
    only_in_json = js_props - py_props
    only_in_pydantic = py_props - js_props
    assert not only_in_json, f"Fields only in JSON Schema: {sorted(only_in_json)}"
    assert not only_in_pydantic, f"Fields only in Pydantic: {sorted(only_in_pydantic)}"


def test_required_sets_match(jsonschema: dict, pydanticschema: dict) -> None:
    js_required = set(jsonschema.get("required", []))
    py_required = set(pydanticschema.get("required", []))
    only_in_json = js_required - py_required
    only_in_pydantic = py_required - js_required
    assert not only_in_json, (
        f"Required in JSON Schema but optional in Pydantic: {sorted(only_in_json)}. "
        "Tighten the Pydantic field with Field(...) to require it."
    )
    assert not only_in_pydantic, (
        f"Required in Pydantic but optional in JSON Schema: {sorted(only_in_pydantic)}. "
        "Add to the JSON Schema 'required' list or relax the Pydantic field."
    )


@pytest.mark.parametrize("field", _ENUM_FIELDS)
def test_enum_members_match(field: str, jsonschema: dict, pydanticschema: dict) -> None:
    js = _jsonschema_enum(jsonschema["properties"][field])
    py = _pydantic_enum(pydanticschema["properties"][field])
    only_in_json = js - py
    only_in_pydantic = py - js
    assert not only_in_json, (
        f"Field '{field}': enum values only in JSON Schema: {sorted(only_in_json)}. "
        "Add to the Pydantic Literal."
    )
    assert not only_in_pydantic, (
        f"Field '{field}': enum values only in Pydantic: {sorted(only_in_pydantic)}. "
        "Add to the JSON Schema enum (or remove from the Pydantic Literal)."
    )
