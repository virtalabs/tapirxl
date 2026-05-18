"""Smoke test: `mdt parse <pcap> --json` emits schema-conformant InventoryRecord JSONL."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent.parent / "fixtures" / "synthetic_philips_demo.pcap"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "inventory_record.schema.json"

_INVENTORY_KEYS: frozenset[str] = frozenset(
    {
        "hostname",
        "ip_address",
        "mac_address",
        "vendor",
        "product",
        "version",
        "device_class",
        "open_ports",
        "confidence",
    }
)


def test_parse_json_emits_inventory_records() -> None:
    """`mdt parse <pcap> --json` emits one schema-conformant InventoryRecord per host."""
    if not FIXTURE_PCAP.exists():
        pytest.skip(f"Fixture PCAP not found: {FIXTURE_PCAP}")
    if not SCHEMA_PATH.exists():
        pytest.skip(f"Schema not found: {SCHEMA_PATH}")

    from typer.testing import CliRunner

    from tapirxl.cli import app

    schema = json.loads(SCHEMA_PATH.read_text())
    vendor_enum = set(schema["properties"]["vendor"]["enum"])
    product_enum = set(schema["properties"]["product"]["enum"])
    device_class_enum = set(schema["properties"]["device_class"]["enum"])
    confidence_enum = set(schema["properties"]["confidence"]["enum"])

    runner = CliRunner()
    result = runner.invoke(app, ["parse", str(FIXTURE_PCAP), "--json"])
    assert result.exit_code == 0, f"CLI exited {result.exit_code}:\n{result.output}"

    # CliRunner mixes stderr+stdout in result.output; parser writes progress
    # logs to stderr and JSONL to stdout, so filter to lines that parse as
    # JSON objects with the expected schema key set.
    records: list[dict] = []
    for line in result.output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and set(obj.keys()) == _INVENTORY_KEYS:
            records.append(obj)

    assert records, "Expected at least one InventoryRecord JSONL line on stdout"

    for record in records:
        assert record["vendor"] in vendor_enum
        assert record["product"] in product_enum
        assert record["device_class"] in device_class_enum
        assert record["confidence"] in confidence_enum
        assert isinstance(record["open_ports"], list)
        assert all(isinstance(p, int) and 0 <= p <= 65535 for p in record["open_ports"])
        assert isinstance(record["ip_address"], str)
        assert isinstance(record["mac_address"], str)
