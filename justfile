# TapirXL justfile — https://just.systems/man/en/

set dotenv-load

# Install project deps (including dev group)
install:
    uv sync --dev

# Format
fmt:
    uv run ruff format src/ tests/

# Lint
lint:
    uv run ruff check src/ tests/

# Run tests
test:
    uv run pytest

# Type-check
typecheck:
    uv run mypy src/

# Regenerate synthetic PCAP fixture
fixture:
    uv run tapirxl fixtures

# Parse PCAP → InventoryRecord JSONL (schema: schemas/inventory_record.schema.json)
parse PCAP:
    uv run tapirxl parse {{PCAP}} --json

# Parse PCAP → full HostEnvelope JSONL (raw deterministic shape, all pipeline blocks)
parse-verbose PCAP:
    uv run tapirxl parse {{PCAP}}
