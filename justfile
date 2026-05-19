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

# Validate the Vector configs (no sockets, no daemon).
# The two configs share a transform name, so they must be validated
# independently (Vector merges multiple --config-toml args). Stub env
# vars satisfy the http sink's required interpolation; `validate` does
# not open sockets, so the stub values never reach the network.
# VECTOR_DATA_DIR is redirected to a tempdir because /var/lib/vector
# (the in-container default) does not exist on native dev machines.
vector-validate:
    #!/usr/bin/env sh
    set -e
    export VECTOR_DATA_DIR="${VECTOR_DATA_DIR:-${TMPDIR:-/tmp}/tapirxl-vector-data}"
    export BLUEFLOW_URL="${BLUEFLOW_URL:-http://localhost:0}"
    export BLUEFLOW_TOKEN="${BLUEFLOW_TOKEN:-validate-stub}"
    export TAPIRXL_INVENTORY_FILE="${TAPIRXL_INVENTORY_FILE:-/var/lib/tapirxl/inventory.jsonl}"
    mkdir -p "$VECTOR_DATA_DIR"
    vector validate configs/upload-vector.toml
    vector validate configs/upload-vector.pcap.toml
    vector validate configs/upload-vector.dryrun.toml

# Run the inline [[tests]] stanzas in configs/upload-vector.tests.toml.
# Same env-var indirection as `vector-validate` — `vector test` parses the
# full sink config before running the test stanzas.
vector-test:
    #!/usr/bin/env sh
    set -e
    export VECTOR_DATA_DIR="${VECTOR_DATA_DIR:-${TMPDIR:-/tmp}/tapirxl-vector-data}"
    export BLUEFLOW_URL="${BLUEFLOW_URL:-http://localhost:0}"
    export BLUEFLOW_TOKEN="${BLUEFLOW_TOKEN:-test-stub}"
    export TAPIRXL_INVENTORY_FILE="${TAPIRXL_INVENTORY_FILE:-/var/lib/tapirxl/inventory.jsonl}"
    mkdir -p "$VECTOR_DATA_DIR"
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

# Build the unified demo image (`tapirxl:demo-dev`).
#
# This is the A2 image — parser + Vector binary + mode-switching entrypoint in
# one container. Mirrors the future `virtalabsinc/tapirxl:demo-<tag>` push
# (deferred to A3 / release.yml). See packaging/docker/demo/Dockerfile.
docker-build-demo:
    docker build \
        -f packaging/docker/demo/Dockerfile \
        -t tapirxl:demo-dev \
        .

# Containerized dry-run of the unified demo image.
#
# Mounts configs/upload-vector.dryrun.toml over the baked-in pcap config at
# /etc/vector/upload-vector.pcap.toml so Vector writes translated
# AssetUpsertPayload JSONL to stdout instead of PUTting to BlueFlow. No
# socket is opened; stub BLUEFLOW_URL / BLUEFLOW_TOKEN satisfy the
# entrypoint's required-env checks without leaving the container.
docker-dry-run-demo PCAP:
    #!/usr/bin/env sh
    set -e
    PCAP_ABS=$(cd "$(dirname {{PCAP}})" && pwd)/$(basename {{PCAP}})
    PCAP_DIR=$(dirname "$PCAP_ABS")
    PCAP_FILE=$(basename "$PCAP_ABS")
    docker run --rm \
        -v "$(pwd)/configs/upload-vector.dryrun.toml:/etc/vector/upload-vector.pcap.toml:ro" \
        -v "$PCAP_DIR:/pcap:ro" \
        -e TAPIRXL_MODE=pcap \
        -e TAPIRXL_PCAP_PATH="/pcap/$PCAP_FILE" \
        -e BLUEFLOW_URL="${BLUEFLOW_URL:-http://localhost:0}" \
        -e BLUEFLOW_TOKEN="${BLUEFLOW_TOKEN:-dryrun-placeholder}" \
        tapirxl:demo-dev
