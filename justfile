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
    uv run mdt fixtures

# Parse PCAP → InventoryRecord JSONL (schema: schemas/inventory_record.schema.json)
parse PCAP:
    uv run mdt parse {{PCAP}} --json

# Parse PCAP → full HostEnvelope JSONL (raw deterministic shape, all pipeline blocks)
parse-verbose PCAP:
    uv run mdt parse {{PCAP}}

# Full pipeline → reports/
agent PCAP:
    uv run mdt agent {{PCAP}}

# Full pipeline → JSONL stdout
agent-json PCAP:
    uv run mdt agent {{PCAP}} --json

# Triage only (no Ollama required)
agent-no-llm PCAP:
    uv run mdt agent {{PCAP}} --no-llm

# Compile FuseSignals → agents/compiled_fusion.json
compile-fusion:
    uv run mdt agent --compile --compiled-json agents/compiled_fusion.json

# Compile NormalizeSignal → agents/compiled_normalize.json
compile-normalize:
    uv run mdt agent --compile-normalize --compiled-normalize-json agents/compiled_normalize.json
