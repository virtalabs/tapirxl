# TapirXL — Architecture

| Field    | Value                                                      |
| -------- | ---------------------------------------------------------- |
| Document | Deterministic Passive Medical-Device Identification        |
| Version  | 4.0 — stable architecture (supersedes v3.0 monolith)       |
| Date     | 2026-05-18                                                 |
| Status   | Authoritative for `main`                                   |

---

## §0 — Document History

v4.0 is a ground-up rewrite scoped to the `main` branch after the deterministic /
agent split. The v3.0 unified document described the monolith (deterministic
parser + DSPy/Ollama LM tiers + Jinja markdown reporter); its agent-tier
chapters now live on the `experimental/agent` branch alongside the code they
describe.

---

## §1 — Purpose and Domain

Given a PCAP file, produce a deterministic per-host inventory of medical and
medical-adjacent devices observable on the wire, with no active probing and no
LM inference. The output is consumed by humans (piped through `jq`), other
tooling (CSV pipelines, SIEM ingest), and downstream asset-management services
over the `HostEnvelope` JSONL wire contract.

The core domain is the **deterministic transformation of captured network
packets into a per-host inventory of medical-adjacent devices**, subject to
four irreducible constraints:

1. **Read-only.** No packets emitted, no DNS queries against observed names, no
   sockets opened by any extractor. Static-file reads only.
2. **Offline first.** PCAP files are the primary input. Streaming sources are
   adapters over the same domain model.
3. **Deterministic.** Identical input PCAPs produce bit-identical JSONL output
   across every commit.
4. **PHI-safe.** DICOM `(0010,*)` tags and HL7 PID-3/5/7/8 fields are redacted
   before any record leaves an extractor.

What makes this a coherent domain — not just "a parser" — is the
classification work that operates only on what packets reveal: vendor arcs,
service-type codes, fingerprint shape, contradiction patterns. The
parser-as-aggregator is the differentiating asset.

### 1.1 Scope

| Category   | In scope                                                                 | Out of scope                                       |
| ---------- | ------------------------------------------------------------------------ | -------------------------------------------------- |
| Input      | PCAP file path                                                           | Live capture (deferred adapter)                    |
| Output     | `HostEnvelope` JSONL, `InventoryRecord` JSONL                            | Markdown reports, REST/SSE, asset-store mutations  |
| Inference  | Rule-based labelers, consensus, floor triggers, contradiction codes      | LM normalization, fusion, ReAct                    |
| Storage    | None (stdin/stdout pipes)                                                | Persistent asset records, drift events             |
| Network    | None (parser does not speak the network)                                 | Anything                                           |

---

## §2 — Ubiquitous Language

The following terms have one and only one meaning across the codebase.

| Term                    | Meaning                                                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Host**                | A MAC address observed in the capture. Identity equals MAC (`host_id`); IP is observational, not identifying.                                            |
| **Signal**              | One protocol-level observation about a host (DICOM A-ASSOC, WS-D Hello, DHCP Discover, etc.).                                                            |
| **HostEnvelope**        | The aggregate root: every signal observed for one MAC, plus deterministic labels, triage routing, and ambiguity metadata. Wire contract for consumers.   |
| **Pipeline**            | One of three concurrent extraction families (broadcast / session / DPI). Pipelines are bands of signal types, not threads.                               |
| **Deterministic label** | A label assigned by per-pipeline rule (no LM), with a `HIGH` / `MEDIUM` / `LOW` confidence.                                                              |
| **Consensus**           | Cross-pipeline aggregate of deterministic labels with a single confidence value.                                                                         |
| **Floor trigger**       | A categorical signal that forces a host out of `STAMP_LOW` even at `signal_count == 1` (e.g. `MEDICAL_UUID_PREFIX`, `HL7_CLINICAL_INTERFACE`).           |
| **Contradiction**       | A coded conflict between two signals (`C1`..`C4`). Routing-significant but never auto-fails a host.                                                      |
| **Ambiguity**           | A field value not deterministically matchable to a known label. Stored verbatim in `lm_envelope.ambiguous_fields[]` for downstream consumption.          |
| **Routing**             | The triage decision for a host, drawn from a closed enum (see §6).                                                                                       |
| **InventoryRecord**     | The public projection of one host's envelope to the wire format defined in `schemas/inventory_record.schema.json`.                                       |
| **OUI**                 | The 24-bit Layer-2 vendor prefix lookup. A supporting subdomain.                                                                                          |

---

## §3 — Subdomain Map

Subdomains follow Evans' three categories: **Core** (the differentiating
asset), **Supporting** (custom work serving the core), **Generic** (commodity
plumbing).

| #   | Subdomain                  | Classification | Lives in                              | Responsibility                                                            |
| --- | -------------------------- | -------------- | ------------------------------------- | ------------------------------------------------------------------------- |
| 3.1 | Signal Extraction          | Supporting     | `src/tapirxl/parser/extractors/`      | Protocol-specific reads → per-packet signal records. PHI redacted at source. |
| 3.2 | Host Envelope Aggregation  | **Core**       | `src/tapirxl/parser/envelope_builder.py` | Merge signals into per-MAC `HostEnvelope`. Aggregate root invariants.     |
| 3.3 | Deterministic Labeling     | **Core**       | `src/tapirxl/parser/deterministic.py` | Per-pipeline labelers + cross-pipeline consensus.                         |
| 3.4 | Triage / Routing           | **Core**       | `src/tapirxl/parser/triage.py`        | Cross-pipeline contradiction scan + routing decision.                     |
| 3.5 | Inventory Projection       | **Core**       | `src/tapirxl/core/inventory_record.py` + `src/tapirxl/schemas/inventory.py` | `HostEnvelope` → `InventoryRecord`. CPE slugs, device class, open ports.  |
| 3.6 | Wire Projection            | **Core**       | `src/tapirxl/parser/serialize.py` + `src/tapirxl/schemas/envelope.py` | Flat runtime dict → typed `HostEnvelope`. Single seam.                    |
| 3.7 | Static Reference Data      | Supporting     | `src/tapirxl/parser/tables.py` + `static/*.json` + `static/ieee_oui.txt` | OUI lookup, DICOM impl-UID arcs, Fingerbank DHCP, HL7 sending apps, SNMP. |
| 3.8 | Fixture Generation         | Supporting     | `src/tapirxl/fixtures/`               | Synthetic Philips demo PCAP for regression and demos.                     |
| 3.9 | Ports & Adapters           | Generic        | `src/tapirxl/parser/ports.py` + `src/tapirxl/parser/adapters/` | `PacketSource`, `EnvelopeSink` Protocols; pyshark + stdout adapters.       |
| 3.10| CLI                        | Generic        | `src/tapirxl/cli.py` + `src/tapirxl/parser/cli.py` | Typer entry points. Thin wrappers, no domain logic.                       |

---

## §4 — Toolchain

| Tool             | Role                                                                |
| ---------------- | ------------------------------------------------------------------- |
| Python 3.14      | Runtime                                                             |
| uv               | Resolver + venv + lockfile                                          |
| ruff             | Linter + formatter                                                  |
| just             | Task runner                                                         |
| pytest           | Test runner                                                         |
| mypy             | Type checker (dev)                                                  |
| pyshark          | PCAP dissection (depends on `tshark` PATH)                          |
| pydantic v2      | Wire-contract models                                                |
| typer            | CLI                                                                 |
| Vector           | Log shipper to BlueFlow (see §12). Binary pin in `packaging/docker/vector/Dockerfile`. |

`pyproject.toml` is the single source of project metadata. Recipes live in
[`justfile`](../justfile).

---

## §5 — Package Layout

```
src/tapirxl/
├── core/                  # MAC, OUI, PHI, CPE enums, IP sort — no project imports
│   ├── enums.py
│   ├── inventory_record.py     # HostEnvelope → InventoryRecord projection
│   ├── ip.py
│   ├── mac.py
│   ├── oui.py
│   ├── phi.py
│   └── ws_tables.py
├── parser/                # Deterministic only — no LM imports
│   ├── adapters/
│   │   ├── pyshark_source.py
│   │   └── stdout_sink.py
│   ├── extractors/        # One file per protocol
│   ├── _helpers.py
│   ├── cli.py             # `tapirxl-parse` entry
│   ├── deterministic.py   # Per-pipeline labelers + consensus
│   ├── envelope_builder.py
│   ├── pipeline.py
│   ├── ports.py           # PacketSource, EnvelopeSink Protocols
│   ├── serialize.py       # Flat dict → typed HostEnvelope projection
│   ├── tables.py
│   └── triage.py
├── schemas/               # Pydantic v2 wire contracts
│   ├── envelope.py        # HostEnvelope (typed wire format)
│   └── inventory.py       # InventoryRecord (public CLI projection)
├── fixtures/              # Synthetic PCAP generator
└── cli.py                 # Typer app — wires subcommands to parser/ + fixtures/
```

`schemas/inventory_record.schema.json` at the repository root is the JSON
Schema mirror of [`schemas/inventory.py`](../src/tapirxl/schemas/inventory.py).
Static reference data (`ieee_oui.txt`, `fingerbank_dhcp_55.json`,
`dicom_impl_uid_arcs.json`, `hl7_sending_apps.json`,
`snmp_sysobjectid_arcs.json`) lives under `static/`.

---

## §6 — Three Pipelines

Each pipeline is a band of protocol signal types, not a thread. All three feed
the same per-MAC `HostEnvelope`.

| #   | Name                  | Protocols                                                                                              | Latency       |
| --- | --------------------- | ------------------------------------------------------------------------------------------------------ | ------------- |
| 1   | Broadcast / multicast | WS-Discovery, mDNS, DNS-SD, LLMNR, SSDP, ARP, Capsule MDIP                                             | < 60 s        |
| 2   | Session / passive OS  | TCP SYN fingerprint, TLS Hello (SNI), SMB2 Negotiate, NTLMSSP, Kerberos, DNS, SSH                      | first connect |
| 3   | Event-driven DPI      | DICOM A-ASSOC, DHCP (option 12/55/60 + Fingerbank), HL7 MLLP (PHI-scrubbed), SNMP (sysDescr/sysOID)    | event-bound   |

Block presence in the envelope **is** the signal; missing blocks are absent
(`None`), never empty objects.

The single-pass pyshark sweep that drives extraction lives in
[`parser/pipeline.py`](../src/tapirxl/parser/pipeline.py). Per-protocol
extraction lives in [`parser/extractors/`](../src/tapirxl/parser/extractors/).

---

## §7 — Wire Contracts

Two wire contracts cross the parser boundary.

### 7.1 `HostEnvelope` — Default `tapirxl parse <pcap>` output

Typed model: [`src/tapirxl/schemas/envelope.py`](../src/tapirxl/schemas/envelope.py).

The aggregate root. Top-level fields are closed (`extra="forbid"`); sub-block
models retain `extra="allow"` so extractor-side field drift is tolerated until
those shapes are tightened. Pipeline blocks (`pipeline_1`, `pipeline_2`,
`pipeline_3`) are `None` when the pipeline did not fire.

Projection from the flat runtime envelope produced by
[`envelope_builder.py`](../src/tapirxl/parser/envelope_builder.py) into the
typed shape happens in
[`parser/serialize.py:to_envelope`](../src/tapirxl/parser/serialize.py),
called from [`parser/cli.py`](../src/tapirxl/parser/cli.py) before the JSONL
emit.

Top-level fields:

- `host_id` (MAC, primary key), `oui_vendor`, `ip_observations[]`
- `first_seen`, `last_seen`
- `ethernet`
- `pipeline_1`, `pipeline_2`, `pipeline_3` — `None` when not fired
- `triage` — `signal_count`, `pipelines_fired`, `floor_triggers`,
  `deterministic_consensus`, `contradiction_codes`, `routing`
- `lm_envelope.ambiguous_fields[]` — verbatim ambiguity records for downstream
  consumers

### 7.2 `InventoryRecord` — `tapirxl parse <pcap> --json` output

Pydantic model: [`src/tapirxl/schemas/inventory.py`](../src/tapirxl/schemas/inventory.py).
JSON Schema mirror: [`schemas/inventory_record.schema.json`](../schemas/inventory_record.schema.json).

Nine fields, enum-bounded where enumerable: `hostname`, `ip_address`,
`mac_address`, `vendor`, `product`, `version`, `device_class`, `open_ports`,
`confidence`. Vendor and product slugs align with `cpe:2.3` slots 3 and 4 for
future CVE/CPE binding.

The projection from `HostEnvelope` is implemented in
[`core/inventory_record.py:build_jsonl_record`](../src/tapirxl/core/inventory_record.py).
This is the public demo output and the stable contract for non-TapirXL
consumers; the `--json` flag's semantics do not change without a major
package version bump.

---

## §8 — Triage Routing

`route_host` in [`parser/triage.py`](../src/tapirxl/parser/triage.py) writes
exactly one of four values to `triage.routing`. The enum is closed and
enforced at the schema level via `Literal`:

```
SKIP                 host had no signals worth keeping
STAMP_LOW            one signal, no floor trigger → recorded with LOW confidence
DETERMINISTIC_FINAL  HIGH consensus, no ambiguity, no contradictions
AMBIGUOUS            everything else; downstream consumers may reason further
```

First-match-wins ordering:

1. `signal_count == 0` and no expert flags → `SKIP`
2. Any `contradiction_codes` populated → `AMBIGUOUS` (contradictions are
   preserved; STAMP_LOW would lose them)
3. `signal_count == 1` and no `floor_triggers` → `STAMP_LOW`
4. HIGH consensus, no ambiguous fields → `DETERMINISTIC_FINAL`
5. Everything else → `AMBIGUOUS`

Floor triggers (see [`envelope_builder.finalize_envelope_from_records`](../src/tapirxl/parser/envelope_builder.py))
force a host out of `STAMP_LOW` even at `signal_count == 1`:
`MEDICAL_UUID_PREFIX`, `CLINICAL_SERVICE`, `EXPERT_ANOMALY`,
`DICOM_VENDOR_ARC`, `DICOM_PHILIPS_IMAGE_UID`, `DHCP_MEDICAL_VENDOR_CLASS`,
`HL7_CLINICAL_INTERFACE`, `SNMP_MEDICAL_SYSDESCR`, plus the SSDP variants.

Contradiction codes (`C1`..`C4`) are produced by `contradiction_scan` and
preserve the conflicting signals for downstream consumers — they never
auto-fail a host.

---

## §9 — PHI Redaction

Mandatory before any record is written to the envelope. Implemented in
[`src/tapirxl/core/phi.py`](../src/tapirxl/core/phi.py) and applied at
extraction time inside each protocol extractor (HL7 PID-3/5/7/8, DICOM
`(0010,*)` group). Institution name `(0008,0080)` is retained — it is not PHI
under HIPAA's definitions and is operationally useful for inventory.

Downstream consumers re-assert the invariant at ingest as a defense-in-depth
check but never perform discovery-time redaction.

---

## §10 — Architectural Invariants

Binding for every PR.

| #   | Invariant                                                                                                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A1  | **MAC is primary key.** `HostEnvelope.host_id` is a normalized lowercase colon-delimited MAC. IPs are observational and may change across captures for the same host. Never key state on IP.                            |
| A2  | **Absent ≠ empty.** Pipeline blocks are `None` when not fired. Empty dicts are a bug.                                                                                                                                    |
| A3  | **PHI redacted at the source.** DICOM `(0010,*)` and HL7 PID-3/5/7/8 are redacted in the extractor before the field touches an envelope.                                                                                |
| A4  | **Extractors are read-only.** No sockets, no DNS lookups against observed names, no packet emission. Static-file reads only.                                                                                              |
| A5  | **Bit-identical replay.** Given identical PCAP bytes and identical static tables, JSONL output is byte-identical across commits. Enforced by the golden regression test against the synthetic fixture.                  |
| A6  | **`core/` is leaf.** `src/tapirxl/core/*` imports nothing from elsewhere in the project except other `core/` modules.                                                                                                    |
| A7  | **Parser is LM-free.** `src/tapirxl/parser/*` does not import `dspy`, `ollama`, `jinja2`, or any model artifact. Reintroducing such an import is a CI-blocking regression.                                              |
| A8  | **Routing enum is closed.** `triage.routing` is exactly one of `{SKIP, STAMP_LOW, DETERMINISTIC_FINAL, AMBIGUOUS}`. Adding a value requires a schema-version bump (A9).                                                  |
| A9  | **Schema versions advance monotonically; fields are additive.** Field additions to `HostEnvelope` or `InventoryRecord` are non-breaking. Removals and renames require a major package version bump.                     |
| A10 | **`InventoryRecord` is the public CLI contract.** `tapirxl parse <pcap> --json` emits one record per host conforming to `schemas/inventory_record.schema.json`. The flag's semantics do not change.                     |
| A11 | **`HostEnvelope` is the wire contract.** `tapirxl parse <pcap>` (no `--json`) emits one envelope per host conforming to `src/tapirxl/schemas/envelope.py`.                                                              |
| A12 | **PHI redaction is upstream, once.** TapirXL redacts at extract time (A3). Downstream consumers re-assert as a defense-in-depth check but never perform discovery-time redaction.                                       |

---

## §11 — CLI Surface

```bash
# Demo-primary: InventoryRecord JSONL on stdout (one record per host)
tapirxl parse <pcap> --json

# Verbose: full HostEnvelope JSONL on stdout (one envelope per host)
tapirxl parse <pcap>

# Regenerate the synthetic Philips demo PCAP
tapirxl fixtures
```

Justfile recipes mirror this:

| Recipe                      | Command                         | Output                |
| --------------------------- | ------------------------------- | --------------------- |
| `just parse PCAP`           | `tapirxl parse PCAP --json`     | InventoryRecord JSONL |
| `just parse-verbose PCAP`   | `tapirxl parse PCAP`            | HostEnvelope JSONL    |
| `just fixture`              | `tapirxl fixtures`              | synthetic PCAP        |
| `just test` / `lint` / `fmt`/ `typecheck` | standard dev recipes |                       |

Entry points (declared in `pyproject.toml`):

- `tapirxl` — the Typer app ([`src/tapirxl/cli.py`](../src/tapirxl/cli.py))
- `tapirxl-parse` — direct call to [`parser/cli.py:main`](../src/tapirxl/parser/cli.py)
- `tapirxl-fixtures` — direct call to [`fixtures/cli.py:main`](../src/tapirxl/fixtures/cli.py)

---

## §12 — Log Shipper (Vector)

Upstream delivery of `InventoryRecord` JSONL to BlueFlow's
`/api/assets/upsert/` endpoint is implemented as a **Vector pipeline**,
not Python code. This is binding (CLAUDE.md N11) and structurally
enforced by the dep guard at
[`tests/compat/test_deps.py`](../tests/compat/test_deps.py): the repo
has no `httpx`, `tenacity`, or `keyring` dependency, and adding any
`uploader/` package would break that test.

### 12.1 Translation contract

| InventoryRecord field | BlueFlow Asset field    | Mapping                                                       |
| --------------------- | ----------------------- | ------------------------------------------------------------- |
| `mac_address`         | `mac_address`           | Verbatim                                                      |
| `ip_address`          | `ip_address`            | Verbatim                                                      |
| `hostname`            | `hostname`              | Omitted when source is `null`                                 |
| `vendor` (slug)       | `manufacturer` (display)| 5-entry lookup; unknown slug passes through                   |
| `product` (slug)      | `model` (display)       | 7-entry lookup; unknown slug passes through                   |
| `version`             | `app_sw_version`        | Omitted when source is `null`                                 |
| `device_class`        | `category`              | Verbatim slug passthrough                                     |
| `open_ports`          | `open_ports_tcp`        | Verbatim (always present, may be `[]`)                        |
| `confidence`          | `external_keys.tapirxl_confidence` | Whole `external_keys` key omitted when source is `null` |

Implemented in [`configs/upload-vector.vrl`](../configs/upload-vector.vrl).
The VRL transform builds a fresh `out` object and assigns it to `.`, so
any unmapped source field is dropped at the transform boundary
(equivalent of Pydantic `extra="forbid"`).

The mapping is the wire contract between this repo and BlueFlow. Tests:

- 8 inline `[[tests]]` stanzas in
  [`configs/upload-vector.tests.toml`](../configs/upload-vector.tests.toml)
  (one per record in the existing inventory golden).
- Byte-identical pipeline test at
  [`tests/regression/test_vector_pipeline.py`](../tests/regression/test_vector_pipeline.py)
  comparing translated output against
  [`tests/regression/golden_synthetic_philips_assets.jsonl`](../tests/regression/golden_synthetic_philips_assets.jsonl).

### 12.2 Pipeline shape

```
InventoryRecord JSONL  ──┐
                          ├──→  [transform: remap (VRL)]  ──→  [http sink → BlueFlow]
  (stdin OR file tail) ──┘                                           │
                                                                     ├──→  disk buffer (1 GiB, drop_newest)
                                                                     └──→  retry budget 600s, full jitter
```

Defined in [`configs/upload-vector.toml`](../configs/upload-vector.toml).
Two source modes share the same transform and sink:

- **stdin** — local dev and `just upload-dry-run PCAP`.
- **file tail** — compose / demo: Vector tails
  `${TAPIRXL_INVENTORY_FILE:-/var/lib/tapirxl/inventory.jsonl}` which the
  parser writes via shell redirection inside a one-shot container.

### 12.3 Delivery guarantees

| Property                 | Value                                                              |
| ------------------------ | ------------------------------------------------------------------ |
| Concurrency              | `request.concurrency = 1` (single-flight)                          |
| Batch size               | `batch.max_events = 1` (one PUT per record)                        |
| Auth                     | `Authorization: Token ${BLUEFLOW_TOKEN}` (DRF, not RFC6750 Bearer) |
| Retry budget             | 600 s wall-clock per record, exponential w/ full jitter            |
| Retry-After (429/503)    | Honored                                                            |
| Durability under failure | 1 GiB on-disk buffer (`buffer.type = "disk"`)                      |
| Overflow behavior        | `drop_newest` — preserves backlog; newer state for a MAC will arrive again |
| Delivery semantics       | At-least-once; BlueFlow upsert is keyed by MAC and idempotent by content |

`Idempotency-Key` header is **deferred** (FR §13) pending a written
answer from the BlueFlow team on upsert idempotency. Adding it later is
one VRL line.

### 12.4 Image contract (consumed by the demo PR)

Packaging lives at [`packaging/docker/`](../packaging/docker/). Two
images are produced from the compose fragment
[`packaging/docker/compose.tapirxl.yaml`](../packaging/docker/compose.tapirxl.yaml):

| Image                   | Entrypoint                  | Declared volumes                                 | User              | Notes                                  |
| ----------------------- | --------------------------- | ------------------------------------------------ | ----------------- | -------------------------------------- |
| `tapirxl-parser:dev`    | `tapirxl` (typer)           | `/pcap` (RO bind), `/var/lib/tapirxl` (RW)       | `tapirxl` uid 10001 | One-shot; parses PCAP → JSONL          |
| `tapirxl-shipper:dev`   | `/usr/bin/vector`           | `/var/lib/tapirxl`, `/var/lib/vector/data`       | `vector` upstream | Long-running; tails inventory file      |

Both non-root. Required env on the shipper: `BLUEFLOW_URL`,
`BLUEFLOW_TOKEN`. Optional: `TAPIRXL_INVENTORY_FILE`, `VECTOR_DATA_DIR`.

### 12.5 Demo compose topology

```
┌─────────────────────────────────────┐   ┌──────────────────────────────────┐
│ packaging/docker/                   │   │ demo PR (separate)               │
│   compose.tapirxl.yaml              │   │   compose.demo.yaml              │
│                                     │   │     include:                     │
│   services:                         │◄──┤       - compose.tapirxl.yaml     │
│     tapirxl-parser   (one-shot)     │   │   services:                      │
│     tapirxl-shipper  (long-running) │   │     blueflow-api                 │
│   volumes:                          │   │     blueflow-db                  │
│     tapirxl-inventory (parser→ship) │   │   playbook (orchestration)       │
│     tapirxl-spool (Vector buffer)   │   │                                  │
└─────────────────────────────────────┘   └──────────────────────────────────┘
```

This PR ships the left half (Tier 1 building blocks). The demo PR adds
BlueFlow services + a network on top via Compose v2.20+ `include:`.

### 12.6 Operator-facing docs

- [`packaging/docker/README.md`](../packaging/docker/README.md) — dev,
  containerized-dev, and demo-integration workflows, plus the
  volume-permissions caveat.
- [`configs/upload.env.example`](../configs/upload.env.example) —
  annotated env template.

### 12.7 Explicitly out of scope (this PR)

| Item                                | Owned by                          |
| ----------------------------------- | --------------------------------- |
| Systemd units                       | Prod-planning PR                  |
| `compose.demo.yaml` (BlueFlow stack) | Demo PR                           |
| Live capture (`-i eth0`, NET_CAP_ADMIN, SPAN-traffic + tcpreplay) | Future parser PR |
| `tapirxl parse --output FILE`       | Small parser follow-up PR         |
| Bounded concurrency (`max_in_flight > 1`) | FR §14 follow-up              |
| `Idempotency-Key`                   | Pending BlueFlow team answer      |

---

## End of Document
