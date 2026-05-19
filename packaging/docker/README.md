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
├── vector/Dockerfile           timberio/vector:0.55.0-debian + the
│                               pinned upload config. Long-running.
└── demo/                       Unified demo image (parser + Vector binary +
    ├── Dockerfile              mode-switching entrypoint). The consolidation
    └── entrypoint.sh           target for `virtalabsinc/tapirxl:demo-<tag>`.
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
  parse /pcap/synthetic_philips_demo.pcap --json \
        --output /var/lib/tapirxl/inventory.jsonl
# Within seconds, Vector tails the new lines and PUTs them to BlueFlow.
docker compose logs --tail 50 tapirxl-shipper
```

`tapirxl parse --output PATH` writes JSONL directly to the shared volume —
no `sh -c` wrapper, no shell redirection, no extra image layer. Stdout is
left empty in this mode; stderr still carries the usual pyshark/tshark
noise. See `tapirxl parse --help`.

## Image contract (consumed by the demo PR)

| Image | Entrypoint | Declared volumes | User | Image size |
| --- | --- | --- | --- | --- |
| `tapirxl-parser:dev` | `tapirxl` (typer; subcommands: `parse`, `fixtures`) | `/pcap` (RO bind), `/var/lib/tapirxl` (RW) | `tapirxl` uid 10001 | ~350 MB |
| `tapirxl-shipper:dev` | `/usr/bin/vector` (default args at CMD) | `/var/lib/tapirxl`, `/var/lib/vector/data` | `vector-runtime` uid 10002 | ~120 MB |
| `tapirxl:demo-dev` (A2) | `tini -- tapirxl-demo-entrypoint` (mode-switches on `$TAPIRXL_MODE`) | `/pcap` (RO bind), `/var/lib/vector/data` | `tapirxl` uid 10001 | ~430 MB |

All three images are non-root.

## Unified demo image (A2)

The unified image at `tapirxl:demo-dev` is the consolidation target for
the demo compose in the separate demo repo. It bakes the parser, Vector
binary, and both Vector configs
([`upload-vector.toml`](../../configs/upload-vector.toml) and
[`upload-vector.pcap.toml`](../../configs/upload-vector.pcap.toml))
into one container with a mode-switching entrypoint
([`demo/entrypoint.sh`](demo/entrypoint.sh)). Compared with the
two-image Tier-1 layout above, it removes the inter-service shared volume
in favor of a direct in-container pipe.

### Mode contract

| `$TAPIRXL_MODE` | Behavior |
| --- | --- |
| `pcap` (default) | One-shot: `tapirxl parse $TAPIRXL_PCAP_PATH --json` piped to `vector --config-toml /etc/vector/upload-vector.pcap.toml` (stdin-only; clean shutdown on EOF); container exits when the pipeline drains. |
| `live` | Stubbed; exits 64 with a message pointing at B1 (live-capture PR). Real implementation lands in B1. |

### Three Vector configs (mode-aligned)

| Config | Source | Sink | Used by |
| --- | --- | --- | --- |
| [`upload-vector.toml`](../../configs/upload-vector.toml) | `file` (tails `$TAPIRXL_INVENTORY_FILE`) | `http` → BlueFlow | Compose long-running (Tier-1 split above) |
| [`upload-vector.pcap.toml`](../../configs/upload-vector.pcap.toml) | `stdin` | `http` → BlueFlow | Demo image `pcap` mode (this section) |
| [`upload-vector.dryrun.toml`](../../configs/upload-vector.dryrun.toml) | `stdin` | `console` (stdout) | Dev recipes / `test_demo_image.py` overlay |

All three share [`upload-vector.vrl`](../../configs/upload-vector.vrl) for
translation. The pcap variant exists because Vector 0.55's topology won't
exit while a `file` source is tailing — fine for compose, fatal for a
one-shot pipe.

### Required environment

| Variable | Modes | Notes |
| --- | --- | --- |
| `BLUEFLOW_URL` | both | Base URL for the BlueFlow HTTP sink. |
| `BLUEFLOW_TOKEN` | both | DRF token; sent as `Authorization: Token <hex>`. |
| `TAPIRXL_PCAP_PATH` | `pcap` only | Path to the PCAP file inside the container (default `/pcap/synthetic_philips_demo.pcap`). |
| `VECTOR_DATA_DIR` | optional | Vector checkpoint + disk buffer location (default `/var/lib/vector/data`). |

### Recipes

```bash
just docker-build-demo                                        # build tapirxl:demo-dev
just docker-dry-run-demo pcap/synthetic_philips_demo.pcap     # dry-run: stdout JSONL, no BlueFlow needed
uv run pytest tests/regression/test_demo_image.py             # byte-identical golden smoke
```

`docker-dry-run-demo` mounts [`configs/upload-vector.dryrun.toml`](../../configs/upload-vector.dryrun.toml)
over the baked-in pcap config at `/etc/vector/upload-vector.pcap.toml` so
Vector writes translated `AssetUpsertPayload` JSONL to stdout instead of
PUTting to BlueFlow. No socket is opened.

### Relationship to the Tier-1 fragment

The two-image fragment ([compose.tapirxl.yaml](compose.tapirxl.yaml))
stays as the building block for compose `include:`-style integration and
remains the canonical reference for the BlueFlow upsert contract. The
unified image is an addition, not a replacement: it is what the demo repo
(C5) consumes, where one container per logical service is simpler
operationally than the parser/shipper split.

### Pushing `virtalabsinc/tapirxl:demo-<tag>`

Pushing the image to Docker Hub is deferred to A3 (Phase 1 CI gate + tag
release workflow). Local builds tag as `tapirxl:demo-dev`; the Docker
Hub tag convention is `virtalabsinc/tapirxl:demo-<semver>` (matching
[`pyproject.toml`](../../pyproject.toml) `version`).

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

## Releasing a demo tag

CI (`.github/workflows/ci.yml`) runs on every PR and push to `main`. The
`integration-smoke` job builds `tapirxl:demo-dev`, runs the byte-identical
demo-image regression, and exercises the full parser → Vector → stub BlueFlow
upsert path (`tests/integration/test_phase1_smoke.py`) on `ubuntu-latest`.

**Push an annotated tag only after CI is green on that commit.** The release
workflow (`.github/workflows/release.yml`) is artifact-scoped — the git tag
itself names the image to build, using `{artifact}-v{semver}`. For the demo
image, that's `demo-v<semver>`. The workflow parses the prefix, looks up the
Dockerfile in its dispatch table, and pushes:

- `virtalabsinc/tapirxl:demo-<semver>` (e.g. `demo-0.3.0` from tag `demo-v0.3.0`)
- `virtalabsinc/tapirxl:demo-latest`

Additional artifacts (e.g. `parser-v*.*.*`, `shipper-v*.*.*`) reuse the same
workflow with one extra `case` line — see `release.yml` for the current map.

Required GitHub repository secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`.

```bash
# After merge + green CI on main:
git tag -a demo-v0.3.0 -m "TapirXL demo image 0.3.0"
git push origin demo-v0.3.0
# Watch the Release workflow in GitHub Actions.
```

Before the first demo-tag push, confirm the 2026-05-18 live BlueFlow smoke
still passes manually (8 × 201, 8 × 200, field assertions on
`GET /api/assets/`) — the stub gate guards packaging regressions but does
not replace a periodic check against real BlueFlow.
