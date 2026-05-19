# TapirXL Docker packaging — Tier 1 building blocks

This directory ships the dev-and-demo containers for the TapirXL parser
and the Vector-based log shipper. Two images, one compose fragment.
**Production deployment** (systemd units, live-capture / NET_CAP_ADMIN,
SPAN-traffic ingestion) is deliberately deferred to a later PR — see
the plan's "Explicitly out of scope" section.

## What's in this directory

```
packaging/docker/
├── README.md                   (this file)
├── compose.tapirxl.yaml        Two TapirXL services, two named volumes.
│                               Designed to be `include:`d from a parent
│                               demo compose that adds BlueFlow services.
├── parser/Dockerfile           python:3.14-slim-bookworm + tshark + uv-managed deps.
│                               Entrypoint: `tapirxl`. One-shot semantics.
└── vector/Dockerfile           timberio/vector:0.55.0-debian + the
                                pinned upload config. Long-running.
```

## Dev workflow (preferred)

Native binaries on your dev machine, no containers:

```bash
brew install vectordotdev/brew/vector   # macOS
# or apt: see https://vector.dev/docs/setup/installation/package-managers/apt/

uv sync --dev                            # tapirxl + tests
just vector-validate                     # syntax + schema check (no sockets)
just vector-test                         # runs the 8 [[tests]] stanzas
just upload-dry-run pcap/x.pcap          # parser | vector dryrun -> stdout JSON
```

The `vector` binary version on PATH must match the pin in
[`vector/Dockerfile`](vector/Dockerfile) (major.minor); this is enforced
by [`tests/regression/test_vector_version_pinned.py`](../../tests/regression/test_vector_version_pinned.py).

## Containerized dev workflow

When you want to validate the images themselves, or you don't want to
install Vector locally:

```bash
just docker-build         # builds tapirxl-parser:dev + tapirxl-shipper:dev
just compose-config       # validates compose.tapirxl.yaml in isolation
just docker-dry-run pcap/x.pcap  # one-shot parser | shipper dryrun in containers
```

`docker-dry-run` runs the parser as a one-shot, redirects its stdout
into a tmpfile inside the container, and feeds it through the shipper
configured against the dryrun config. No BlueFlow service required.

## Demo integration

The upcoming demo PR ships a `compose.demo.yaml` that `include:`s this
fragment and adds the BlueFlow service stack on top:

```yaml
# compose.demo.yaml (lives in the demo PR / demo repo)
include:
  - tapirxl/packaging/docker/compose.tapirxl.yaml

services:
  blueflow-api:
    image: blueflow/api:demo
    networks: [demo]
    ports: ["8000:8000"]
    # ...
  blueflow-db:
    image: postgres:16
    networks: [demo]
    # ...

networks:
  demo:
```

Required environment for the shipper:

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `BLUEFLOW_URL` | recommended | `http://blueflow-api:8000` | Base URL; the path `/api/assets/upsert/` is appended in `configs/upload-vector.toml`. |
| `BLUEFLOW_TOKEN` | **required** | _(none)_ | DRF token; sent as `Authorization: Token <hex>`. Compose interpolation will fail-fast if unset. |
| `TAPIRXL_INVENTORY_FILE` | optional | `/var/lib/tapirxl/inventory.jsonl` | The shared-volume path Vector tails. |
| `VECTOR_DATA_DIR` | optional | `/var/lib/vector/data` | Vector checkpoint + disk buffer location. |

Shared volumes:

| Volume | Writer | Reader | Purpose |
| --- | --- | --- | --- |
| `tapirxl-inventory` | `tapirxl-parser` | `tapirxl-shipper` (RO) | InventoryRecord JSONL handoff. |
| `tapirxl-spool` | `tapirxl-shipper` | — | Vector's disk buffer + file source checkpoints. |

## Driving the demo (one-shot)

```bash
# In the demo PR's directory:
docker compose up -d blueflow-api blueflow-db tapirxl-shipper
docker compose run --rm tapirxl-parser \
  sh -c 'tapirxl parse /pcap/synthetic_philips_demo.pcap --json \
         >> /var/lib/tapirxl/inventory.jsonl'
# Within seconds, Vector tails the new lines and PUTs them to BlueFlow.
docker compose logs --tail 50 tapirxl-shipper
```

### Known wart: parser one-shot uses `sh -c` redirection

`tapirxl parse` writes to stdout only; there is no `--output FILE` flag
today. The one-shot redirects inside the container with `sh -c '...
>> /var/lib/tapirxl/inventory.jsonl'`. A `--output FILE` flag is a small
follow-up parser PR and would let the demo drop the `sh -c` wrapper.

## Image contract (consumed by the demo PR)

| Image | Entrypoint | Declared volumes | User | Image size |
| --- | --- | --- | --- | --- |
| `tapirxl-parser:dev` | `tapirxl` (typer; subcommands: `parse`, `fixtures`) | `/pcap` (RO bind), `/var/lib/tapirxl` (RW) | `tapirxl` uid 10001 | ~350 MB |
| `tapirxl-shipper:dev` | `/usr/bin/vector` (default args at CMD) | `/var/lib/tapirxl`, `/var/lib/vector/data` | `vector-runtime` uid 10002 | ~120 MB |

Both images are non-root.

### Volume-permissions story

The parser writes `/var/lib/tapirxl/inventory.jsonl` as uid 10001 with
default file mode 644 (owner rw, group r, world r). The shipper reads
that file as uid 10002. Mode 644 grants world read, so the cross-uid
read works without explicit group alignment. The shipper mounts the
shared volume `:ro` (see [`compose.tapirxl.yaml`](compose.tapirxl.yaml))
to enforce write-isolation between the two services.

The shipper's writable `/var/lib/vector/data` is its own named volume
(`tapirxl-spool`), owned by uid 10002 at image-build time; compose
preserves that ownership on first mount.

If the demo PR changes uids on either side, the easiest fix is to keep
the shared inventory volume world-readable and the buffer volume
owned by the shipper uid only.

## Inspecting buffer state at runtime

```bash
docker exec tapirxl-shipper du -sh /var/lib/vector/data
```

The shipper config caps the disk buffer at 1 GiB with `when_full =
"drop_newest"` — newer records are dropped under sustained backpressure
rather than evicting backlog. See `configs/upload-vector.toml`.

## Updating the Vector pin

1. Update the `FROM` tag in [`vector/Dockerfile`](vector/Dockerfile).
2. Rebuild the image: `just docker-build`.
3. Update your local `vector` binary to match (major.minor).
4. Re-run `just vector-test` and `uv run pytest tests/regression/`.
5. If the byte-identical pipeline test fails, the new Vector's JSON
   serializer changed ordering — regenerate goldens with `just
   golden-regenerate` and review the diff carefully.
