# TapirXL — Claude Code Project Context

**What:** Passive medical-device identification from PCAP files. Three concurrent
signal-extraction pipelines feed a canonical per-MAC `HostEnvelope`; hosts are
classified deterministically on `main` (no LM inference). Public output is
`InventoryRecord` JSONL (`tapirxl parse --json`); verbose output is typed
`HostEnvelope` JSONL. Upstream delivery to BlueFlow is a Vector pipeline, not
Python code.

**Source of truth:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) in this repo.
This file is a coding-agent-optimized distillation for agents working on `main`.

---

## Toolchain (main)

```bash
uv sync                        # install deps (Python 3.14)
uv run ruff format             # format
uv run ruff check              # lint
uv run pytest                  # test
just fixture                   # regenerate synthetic_philips_demo.pcap
just parse pcap/x.pcap         # InventoryRecord JSONL on stdout
just parse-verbose pcap/x.pcap # raw HostEnvelope JSONL on stdout
```

Entry points on `main` (from `[project.scripts]`): `tapirxl`, `tapirxl-parse`, `tapirxl-fixtures`.

### Log shipper (Vector)

Upstream delivery to BlueFlow's `/api/assets/upsert/` is implemented as a
Vector pipeline at [`configs/upload-vector.toml`](configs/upload-vector.toml),
not as Python code. See N11 below and `docs/ARCHITECTURE.md §12` for the
full contract.

```bash
brew install vectordotdev/brew/vector   # or apt: vector.dev/docs/setup/installation/

just vector-validate          # config syntax + schema check (no sockets)
just vector-test              # runs the 8 [[tests]] stanzas
just upload-dry-run pcap/x.pcap   # parser | vector dryrun -> stdout JSON
just docker-build             # builds tapirxl-parser:dev + tapirxl-shipper:dev
just compose-config           # validates packaging/docker/compose.tapirxl.yaml
just docker-dry-run pcap/x.pcap   # containerized parse → Vector dryrun
```

Architectural invariants A1–A14 are defined in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Agent rules N1–N12 below are the enforcement checklist for coding agents.

The Vector binary version is pinned in
[`packaging/docker/vector/Dockerfile`](packaging/docker/vector/Dockerfile)'s
`FROM` tag and enforced by
[`tests/regression/test_vector_version_pinned.py`](tests/regression/test_vector_version_pinned.py)
— same byte-equality discipline as `pyshark==0.6`.

The agent tier (`tapirxl agent`, `tapirxl-agent`, `just agent`, `just agent-no-llm`,
`just compile-fusion`, `just compile-normalize`) and its DSPy/Ollama/Jinja
dependencies live on the `experimental/agent` branch only — see "Branching
Model" below.

---

## Bounded Contexts

| BC | Location | Role on `main` |
| --- | --- | --- |
| **TapirXL Stable** | `main` | Parser + Vector shipper + fixtures |
| **TapirXL Agent** | `experimental/agent` branch only | LM normalize, fusion, markdown reports — frozen |
| **BlueFlow** | external repo | Consumes translated `Asset` payloads via Vector |

`HostEnvelope` JSONL is the cross-BC wire contract. `InventoryRecord` JSONL is
the public consumer projection. Neither changes without a coordinated version bump.

---

## Package Layout (`src/tapirxl/` on `main`)

```
core/           # MAC, OUI, PHI redact, CPE enums, IP sort — no project imports
schemas/        # pydantic v2: HostEnvelope, InventoryRecord; migrations in schemas/migrations/
parser/         # deterministic only — NO dspy, NO LM imports
  extractors/   # one file per protocol (ws_discovery, mdns, dns_sd, llmnr, ssdp,
                #   capsule_mdip, arp, tcp_syn, tls_sni, smb2, kerberos, dns, ssh,
                #   dicom, dhcp, hl7, snmp, expert)
  pipeline.py   # single-pass pyshark sweep → [SignalObservation]
  envelope_builder.py  # merge observations into per-MAC runtime dict
  serialize.py       # flat dict → typed HostEnvelope (emit boundary)
  deterministic.py     # per-pipeline labelers + consensus
  triage.py            # contradiction scan + routing (4-value enum)
  tables.py            # static lookup tables
  ports.py             # PacketSource, EnvelopeSink (typing.Protocol)
  adapters/            # pyshark_source, stdout_sink
fixtures/              # manifest-driven synthetic PCAP generator
  manifest.py          # Pydantic SignalManifest schema (no I/O)
  loader.py            # TOML parse, profile merge, _hex decode
  generator.py         # dispatch assets + flows → timed packets
  signal_manifest.toml # shipped ACMEHOSP demo (example manifest)
  cli.py               # tapirxl-fixtures (--manifest, --output, --seed-time)
  protocols/           # per-protocol emitters (dhcp, dicom, smb2, …)
cli.py          # typer app: parse, fixtures
```

**Shipper (not under `src/` — Vector config + VRL):**

```
configs/
  upload-vector.toml       # prod pipeline: stdin + file → http sink → BlueFlow
  upload-vector.dryrun.toml  # dev: stdin → console stdout
  upload-vector.vrl        # InventoryRecord → Asset translation (single source of truth)
  upload-vector.tests.toml   # 8 inline [[tests]] stanzas
  upload.env.example
packaging/docker/          # tapirxl-parser:dev, tapirxl-shipper:dev images + compose fragment
```

**Artifact dirs (gitignored, writable):** `pcap/`, `reports/` (agent-tier only).

**Version-controlled static data:** `static/ieee_oui.txt`,
`static/fingerbank_dhcp_55.json`, `static/dicom_impl_uid_arcs.json`,
`static/hl7_sending_apps.json`, `static/snmp_sysobjectid_arcs.json`.

**Regression goldens:** `tests/regression/golden_synthetic_philips_{envelope,inventory,assets}.jsonl`.

---

## Hard Rules (enforce always)

| #       | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **N1**  | `agent/` and `parser/` MUST NOT import each other. `core/` and `schemas/` import nothing from the project.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **N2**  | Only `agent/config.py` reads `models.toml`. Only `agent/adapters/ollama_lm.py` constructs `dspy.LM`. Hardcoded model strings anywhere else in `agent/` are a bug.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **N3**  | PHI redaction is mandatory **before** writing to the envelope: HL7 PID-3/5/7/8 and DICOM `(0010,*)` tags → `"<PHI>"`. Institution `(0008,0080)` is OK to keep.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **N4**  | All extractors are read-only. No sockets opened by extractors, no packets sent, no DNS lookups against observed names. Live capture (`tapirxl listen`) uses `pyshark.LiveCapture` for raw-socket **read** only — the parser never transmits probes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **N5**  | (`experimental/agent` only) `NormalizeSignal` output must be verbatim from `candidate_labels` or `OTHER:<reason>`. Enforced post-hoc; non-matching → field left ambiguous, confidence capped at MEDIUM. **No retries** — fix compile-set quality instead.                                                                                                                                                                                                                                                                                                                                                                                                |
| **N6**  | **stdout carries the data contract; everything else goes to stderr.** For commands that emit structured data on stdout (`tapirxl parse`, `tapirxl parse --json`), stdout is reserved for JSONL conforming to the documented schema. Summaries, progress, counts, warnings, banners, paths, debug logs, and any third-party library noise (pyshark, tshark, dspy, ollama) go to stderr. Defense-in-depth: save the real stdout fd at command entry, redirect `sys.stdout → sys.stderr` for the duration of the work phase, then write JSONL using the saved fd. Pre-commit any new CLI command by piping it through `jq -e .` against a known-good fixture. |
| **N7**  | On `experimental/agent`, the `DETERMINISTIC_FINAL` path MUST skip both LM tiers. Any regression there multiplies wall-clock 5–10×. On `main`, LM tiers do not exist — do not add them.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **N8**  | Envelope primary key is MAC (`host_id`). IP is observational. Do not key envelopes on IP.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **N9**  | Adding new fields to the envelope is non-breaking. Renaming or removing fields breaks compiled DSPy modules — treat field names as ABI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| **N10** | (`experimental/agent` only) Fusion reasoning trace MUST explicitly cite any contradiction when `contradiction_flag=True`. On `main`, contradictions are preserved in `triage.contradiction_codes` and route to `AMBIGUOUS`; they never auto-fail a host.                                                                                                                                                                                                                                                                                                                                                                                                      |
| **N11** | Upstream delivery (BlueFlow upsert) is implemented by a Vector pipeline at [`configs/upload-vector.toml`](configs/upload-vector.toml), **not** by Python code. The repo MUST NOT add `httpx`, `tenacity`, `keyring`, or any `uploader/` package. [`tests/compat/test_deps.py`](tests/compat/test_deps.py) enforces the forbidden dep set. Translation lives in [`configs/upload-vector.vrl`](configs/upload-vector.vrl); correctness is guarded by `just vector-test` (8 stanzas) plus the byte-identical golden at [`tests/regression/golden_synthetic_philips_assets.jsonl`](tests/regression/golden_synthetic_philips_assets.jsonl). |
| **N12** | BlueFlow HTTP sink MUST send `Content-Type: application/json` explicitly (`configs/upload-vector.toml` request headers). Vector does not infer this from `encoding.codec = "json"`. Auth is `Authorization: Token ${BLUEFLOW_TOKEN}` (DRF), never `Bearer`. |

---

## Key Schemas (`main`)

### HostEnvelope top-level keys

`host_id` (MAC, primary key), `oui_vendor`, `ip_observations[]`, `first_seen`,
`last_seen`, `ethernet`, `pipeline_1`, `pipeline_2`, `pipeline_3`, `triage`,
`lm_envelope`.

Pipeline blocks are **absent** (not null) when not fired. Each protocol
sub-block carries a `deterministic_label` / `deterministic_confidence` /
`candidate_labels` triplet. `candidate_labels` is non-empty only on a
deterministic miss — it is the only thing `NormalizeSignal` sees.

### Triage routing (first match wins; closed enum on `main`)

```
signal_count == 0                                              → SKIP
signal_count == 1 and not floor_triggers                       → STAMP_LOW
any contradiction_codes populated                             → AMBIGUOUS
HIGH consensus and no ambiguous fields                         → DETERMINISTIC_FINAL
else                                                           → AMBIGUOUS
```

`AMBIGUOUS` means downstream consumers (agent tier on `experimental/agent`, or
BlueFlow) may apply further reasoning. `main` never runs LM tiers.

### Floor triggers (force LM even at low signal_count)

`MEDICAL_UUID_PREFIX` — WS-D `vendor_prefix_hex` ∈ {`5048` PH, `4745` GE, `5349` SI, `4452` DR, `4243` BC}  
`CLINICAL_SERVICE` — `dns_sd_services` contains `_dicom._tcp` / `_hl7._tcp` / `_fhir._tcp`  
`EXPERT_ANOMALY` — `triage.expert_flags` non-empty  
`DICOM_VENDOR_ARC` — `impl_class_uid_vendor_arc` in known set  
`DICOM_PHILIPS_IMAGE_UID` — `image_uid_arc_counts["1.2.840.113704."] > 0`  
`DHCP_MEDICAL_VENDOR_CLASS` — DHCP option-60 matches medical vendor list  
`HL7_CLINICAL_INTERFACE` — `hl7.mllp_detected`  
`SNMP_MEDICAL_SYSDESCR` — sysDescr contains medical vendor prefix

### Confidence rules (binding for FuseSignals)

- **HIGH**: 3+ independent signals agree ∧ no contradictions, OR 2+ signals ∧ floor trigger ∧ no contradictions.
- **MEDIUM**: 2 signals, OR 1 signal + floor trigger, OR any contradiction (hard cap).
- **LOW**: 1 signal, no floor trigger.

### Contradiction codes

`C1 OUI_DICOM_VENDOR_MISMATCH` — flag, often benign  
`C2 MDNS_SPOOF_SUSPECTED` — cap at MEDIUM  
`C3 PHILIPS_WSDISC_VS_NON_PHILIPS_DICOM` — flag for investigation  
`C4 DOMAIN_HOSTNAME_MISMATCH` — log only

### InventoryRecord → envelope mapping (for `_to_cpe_*` and `_to_device_class`)

| Field                | Source priority                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------- |
| `hostname`           | DHCP option 12 → LLMNR self-claim → SMB NTLMSSP `MsvAvNbComputerName`/`workstation` → mDNS A |
| `vendor` (CPE slug)  | DICOM manufacturer/impl_uid → WS-D prefix → DHCP VCI → OUI                                   |
| `product` (CPE slug) | DICOM model/impl_uid → DHCP VCI → WS-D series code                                           |
| `device_class`       | DICOM Modality (CT/MR/US/etc.) → WS-D series → DHCP role → heuristic                         |
| `version`            | DICOM `(0018,1020)` → mDNS TXT firmware key                                                  |

---

## Protocol Extraction Quick Reference

### DICOM (manual PDU parse — no dissector required for core fields)

PDU type byte: `0x01`=A-ASSOC-RQ, `0x02`=A-ASSOC-AC, `0x04`=P-DATA-TF.
AE titles at PDU bytes 10–25 (Called) / 26–41 (Calling), ASCII space-padded.
User-Info at PDU 74+: type `0x52`=ImplClassUID, `0x55`=ImplVersionName.
Vendor arc lookup order (longest-prefix wins): `1.3.46.670589.30.` → Philips Eleva; `1.3.46.670589.40.` → Philips CCP; `1.3.46.` → Philips; `1.3.12.2.1107.` → Siemens; `1.2.840.113619.` → GE.

### HL7 MLLP

Require `tcp.payload[0] == 0x0B`; strip `0x0B` head and `0x1C 0x0D` tail; split on `0x0D`; first segment = MSH. Pull MSH-3/4/5/9/12. Redact PID-3/5/7/8 → `<PHI>` before envelope write.

### WS-Discovery UUID decoding

UUID chars 0–7 = vendor prefix hex (e.g. `50484248`). First 4 chars → vendor:
`5048`=PH (Philips), `4745`=GE, `5349`=SI (Siemens), `4452`=DR (Draeger),
`4243`=BC (Becton). Chars 4–7 decoded to ASCII = series code: `BH`=MX700/800,
`BV`=MX400/450, `GD`=X3/X2.

### TCP SYN OS fingerprint (deterministic)

`TTL=128, MSS=1460, WScale=8, SACK=true` → Win10/11  
`TTL=64, WScale=7, SACK+TS` → Linux recent  
`TTL=64, MSS=1460, WScale=6, TS` → macOS 12+  
`TTL=255` → iOS/Cisco/embedded  
`TTL=128, MSS=512–536` → medical embedded

---

## Agent tier (`experimental/agent` only — not on `main`)

The LM pipeline (`NormalizeSignal`, `FuseSignals`, `FusionOutput`, compiled DSPy
modules, `models.toml`, markdown reports) lives on the `experimental/agent`
branch. Do not add `agent/` imports, `dspy`, or `models.toml` to `main`. When
working on agent features, branch from `experimental/agent` and read that branch's
`agent/` tree and DSPy signatures there.

---

## DSPy Signatures (`experimental/agent` only — do not change field names without recompiling)

```python
class NormalizeSignal(dspy.Signature):
    """Pick verbatim normalization for one ambiguous device-protocol field.
    OUTPUT RULES (binding):
      1. normalized_value MUST be verbatim from candidate_labels when one matches.
      2. Otherwise 'OTHER:<short reason>' and confidence='LOW'.
      3. Use host_context as decision support.
    """
    ambiguous_field_bundle: str = dspy.InputField()  # one ambiguous_fields[] entry as JSON
    envelope_context:       str = dspy.InputField()  # PHI-redacted envelope snippet
    normalized_value:       str = dspy.OutputField() # verbatim candidate OR 'OTHER:…'
    confidence:             str = dspy.OutputField() # HIGH | MEDIUM | LOW

class FuseSignals(dspy.Signature):
    signal_register:    str = dspy.InputField()  # full PHI-redacted envelope JSON
    contradiction_flag: str = dspy.InputField()  # 'true' | 'false'
    contradictions:     str = dspy.InputField()  # pipe-separated descriptions
    floor_triggers:     str = dspy.InputField()  # pipe-separated codes
    expert_flags:       str = dspy.InputField()  # pipe-separated messages
    device_class:       str = dspy.OutputField()
    confidence:         str = dspy.OutputField() # HIGH | MEDIUM | LOW
    reasoning_trace:    str = dspy.OutputField()
    open_questions:     str = dspy.OutputField() # pipe-separated
```

---

## Branching Model

Trunk-based with one long-lived experimental branch:

- **`main`** — stable, releasable. Parser, schemas, core, fixtures, Vector shipper
  configs, Docker packaging. Runtime deps: `pyshark`, `pydantic`, `typer` only.
  No `dspy`, `ollama`, `jinja2`, `httpx`, `tenacity`, `keyring`. No `agent/` subtree.
- **`experimental/agent`** — frozen long-lived branch: DSPy/Ollama agent tier
  (`agent/`, `models.toml`, `tapirxl agent`, compiled modules, markdown reports).
  Rebase onto `main` when the stable layer changes; do not merge agent code into `main`.

Branch from `main` for parser, schemas, core, fixtures, Vector configs, and packaging.
Branch from `experimental/agent` only for LM normalize, fusion, RLM, or report work.

---

## What NOT to Do

- Do not add retry loops to `NormalizeSignal` calls. Fix the training set.
- Do not import `dspy` or `pyshark` in `parser/`. `parser/` is LM-free.
- Do not import `parser/` from `agent/`.
- Do not put model strings (`ollama_chat/...`) anywhere except `models.toml` and `agent/config.py`.
- Do not add `__init__.py` logic that imports across domain boundaries.
- Do not call `dspy.configure(lm=...)` outside of `agent/` initialization.
- Do not pass raw PHI (PID-3/5/7/8, DICOM (0010,\*) tags) to any LM call.
- Do not add `null`/empty pipeline blocks to the envelope — absent means not fired.
- Do not key host state on IP address; always key on MAC (`host_id`).
- Do not write code that sends packets or resolves observed hostnames via DNS.
- Do not write any documentation that references .gitignored documentation.
- Do not add an `uploader/` Python package, `httpx`, `tenacity`, or `keyring` to deliver records to BlueFlow. The shipper is Vector (N11). Translation lives in [`configs/upload-vector.vrl`](configs/upload-vector.vrl); pipeline shape lives in [`configs/upload-vector.toml`](configs/upload-vector.toml).
- Do not hardcode the BlueFlow URL or auth token anywhere. They live in env (`BLUEFLOW_URL`, `BLUEFLOW_TOKEN`); see [`configs/upload.env.example`](configs/upload.env.example).
- Do not omit `Content-Type: application/json` on the Vector http sink (N12).
- Do not merge `agent/` or LM dependencies into `main`. The dep guard blocks it.
