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

# Regenerate golden regression fixtures (commit the result; review the diff first)
golden-regenerate:
    uv run tapirxl parse tests/fixtures/synthetic_philips_demo.pcap \
        > tests/regression/golden_synthetic_philips_envelope.jsonl
    uv run tapirxl parse tests/fixtures/synthetic_philips_demo.pcap --json \
        > tests/regression/golden_synthetic_philips_inventory.jsonl
    uv run tapirxl parse tests/fixtures/synthetic_philips_demo.pcap --json \
        | vector --quiet --config-toml configs/upload-vector.dryrun.toml \
        > tests/regression/golden_synthetic_philips_assets.jsonl

# Validate the Vector configs (no sockets, no daemon)
vector-validate:
    vector validate configs/upload-vector.toml configs/upload-vector.dryrun.toml

# Run the inline [[tests]] stanzas in configs/upload-vector.tests.toml
vector-test:
    vector test configs/upload-vector.toml configs/upload-vector.tests.toml

# Dev pipe: parser -> Vector dryrun -> stdout (translated AssetUpsertPayload JSONL)
upload-dry-run PCAP:
    uv run tapirxl parse {{PCAP}} --json \
        | vector --quiet --config-toml configs/upload-vector.dryrun.toml

# Build both demo images (tapirxl-parser:dev + tapirxl-shipper:dev).
# BLUEFLOW_TOKEN is a placeholder here — the compose file requires the
# variable to be set for interpolation, but `build` does not use the value.
docker-build:
    #!/usr/bin/env sh
    set -e
    BLUEFLOW_TOKEN="${BLUEFLOW_TOKEN:-build-time-placeholder}" \
        docker compose -f packaging/docker/compose.tapirxl.yaml build

# Validate the compose fragment without bringing services up
compose-config:
    #!/usr/bin/env sh
    set -e
    BLUEFLOW_TOKEN="${BLUEFLOW_TOKEN:-test-token-not-used}" \
        docker compose -f packaging/docker/compose.tapirxl.yaml config -q

# Containerized dry-run: parser one-shot in a container, piped to shipper dryrun
docker-dry-run PCAP:
    #!/usr/bin/env sh
    set -e
    BLUEFLOW_TOKEN="${BLUEFLOW_TOKEN:-dryrun-placeholder}" \
        docker compose -f packaging/docker/compose.tapirxl.yaml run --rm -T tapirxl-parser \
            parse "/pcap/$(basename {{PCAP}})" --json \
        | docker run --rm -i -v "$(pwd)/configs:/etc/vector:ro" tapirxl-shipper:dev \
            --quiet --config-toml /etc/vector/upload-vector.dryrun.toml
