# TapirXL — Claude Code Project Context

**What:** Passive medical-device identification from PCAP files. Three concurrent
signal-extraction pipelines feed a canonical per-MAC `HostEnvelope`; hosts are
classified deterministically when possible, and via DSPy LM tiers only on
residual ambiguity. Output: markdown report in `reports/` or JSONL on stdout.

**Source of truth:** `ARCHITECTURE.md` in the PoC repo (VirtaLabs/Medical Device
Traffic/poc). This file is a coding-agent-optimized distillation of it.

---

## Toolchain

```bash
uv sync                        # install deps (Python 3.14)
uv run ruff format             # format
uv run ruff check              # lint
uv run pytest                  # test
just agent-no-llm pcap/x.pcap  # run triage-only (no Ollama required)
just agent pcap/x.pcap         # full pipeline
just fixture                   # regenerate synthetic_philips_demo.pcap
just compile-normalize         # write agents/compiled_normalize.json
just compile-fusion            # write agents/compiled_fusion.json
```

Entry points (from `[project.scripts]`): `mdt`, `mdt-parse`, `mdt-agent`,
`mdt-fixtures`.

---

## Package Layout (`src/tapirxl/`)

```
core/           # MAC, OUI, PHI redact, CPE enums, IP sort — no project imports
schemas/        # pydantic v2: SignalObservation, HostEnvelope, InventoryRecord, FusionOutput
parser/         # deterministic only — NO dspy, NO LM imports
  extractors/   # one file per protocol (ws_discovery, mdns, dns_sd, llmnr, ssdp,
                #   capsule_mdip, arp, tcp_syn, tls_sni, smb2, kerberos, dns, ssh,
                #   dicom, dhcp, hl7, snmp, expert)
  pipeline.py   # single-pass pyshark sweep → [SignalObservation]
  envelope_builder.py  # merge observations into HostEnvelope
  deterministic.py     # per-pipeline labelers (populate deterministic_label / _confidence)
  triage.py            # cross-pipeline consensus, contradiction codes, routing
  tables.py            # static lookup tables
  ports.py             # PacketSource, EnvelopeSink (typing.Protocol)
  adapters/            # pyshark_source, stdout_sink, rest_sink (future)
agent/          # LM tiers + reporting — may import core/ and schemas/, NOT parser/
  config.py     # load_model_config(path) -> ModelConfig  ← ONLY file that reads models.toml
  normalize.py  # Layer 4 orchestration (NormModule calls)
  fusion.py     # Layer 5 orchestration (FuseModule / FuseModuleRLM)
  inventory.py  # envelope + FusionOutput → InventoryRecord + report view model
  ports.py      # LMRunner, EnvelopeSource, InventorySink (typing.Protocol)
  adapters/     # ollama_lm  ← ONLY file that constructs dspy.LM
                # stdin_source, markdown_sink, jsonl_sink
  signatures/   # NormalizeSignal, ContradictSignals, FuseSignals, FuseSignalsRLM
  modules/      # NormModule, FuseModule, FuseModuleRLM
  compile/      # compile_*.py + training_*.py
fixtures/       # synthetic PCAP generator (topology, builder, cli)
cli.py          # typer app; wires subcommands to parser/ and agent/
```

**Artifact dirs (gitignored, writable):**
- `pcap/` — input captures
- `reports/` — markdown output
- `agents/compiled_fusion.json`, `agents/compiled_normalize.json`

**Version-controlled static data:** `static/ieee_oui.txt`,
`static/fingerbank_dhcp_55.json`, `static/dicom_impl_uid_arcs.json`,
`static/hl7_sending_apps.json`, `static/snmp_sysobjectid_arcs.json`.

---

## Hard Rules (enforce always)

| # | Rule |
|---|------|
| **N1** | `agent/` and `parser/` MUST NOT import each other. `core/` and `schemas/` import nothing from the project. |
| **N2** | Only `agent/config.py` reads `models.toml`. Only `agent/adapters/ollama_lm.py` constructs `dspy.LM`. Hardcoded model strings anywhere else in `agent/` are a bug. |
| **N3** | PHI redaction is mandatory **before** writing to the envelope: HL7 PID-3/5/7/8 and DICOM `(0010,*)` tags → `"<PHI>"`. Institution `(0008,0080)` is OK to keep. |
| **N4** | All extractors are read-only. No sockets, no packets sent, no DNS lookups against observed names. |
| **N5** | `NormalizeSignal` output must be verbatim from `candidate_labels` or `OTHER:<reason>`. Enforced post-hoc; non-matching → field left ambiguous, confidence capped at MEDIUM. **No retries** — fix compile-set quality instead. |
| **N6** | When `--json` is set, redirect `sys.stdout` → `sys.stderr` immediately after argparse. Keep the real fd for JSONL only. Third-party libs (dspy, pyshark, ollama) print to stdout unprompted. |
| **N7** | The `DETERMINISTIC_FINAL` code path (≈60–70% of hosts) MUST skip both LM tiers entirely. Any regression here multiplies wall-clock 5–10×. |
| **N8** | Envelope primary key is MAC (`host_id`). IP is observational. Do not key envelopes on IP. |
| **N9** | Adding new fields to the envelope is non-breaking. Renaming or removing fields breaks compiled DSPy modules — treat field names as ABI. |
| **N10** | Fusion reasoning trace MUST explicitly cite any contradiction when `contradiction_flag=True`. Triage caps confidence but never auto-fails. |

---

## `models.toml` (config-driven model selection)

```toml
[provider]
endpoint = "http://localhost:11434"

[lm]           # fusion + RLM orchestrator
model          = "ollama_chat/deepseek-r1:14b"
context_window = 8192
max_tokens     = 1024
temperature    = 0.2

[sub_lm]       # normalize + RLM llm_query sub-calls
model          = "ollama_chat/qwen2.5-coder:3b"
context_window = 32768
max_tokens     = 128
temperature    = 0.0

[sub_lm.fallback]
model          = "ollama_chat/qwen2.5-coder:1.5b"
context_window = 32768
max_tokens     = 128
temperature    = 0.0
```

Resolution order: `--lm` / `--sub-lm` / `--models PATH` CLI flag →
`TAPIRXL_MODELS` env var → `./models.toml` → packaged default.

`dspy.LM` construction in `agent/config.py`:

```python
lm     = dspy.LM(cfg.lm.model, temperature=cfg.lm.temperature,
                 max_tokens=cfg.lm.max_tokens, num_ctx=cfg.lm.context_window)
sub_lm = dspy.LM(cfg.sub_lm.model, temperature=cfg.sub_lm.temperature,
                 max_tokens=cfg.sub_lm.max_tokens, num_ctx=cfg.sub_lm.context_window)
dspy.configure(lm=lm)
norm_module = NormModule()                   # uses dspy.context(lm=sub_lm)
fuse_rlm    = FuseModuleRLM(sub_lm=sub_lm)  # llm_query calls hit sub_lm
```

---

## Key Schemas

### HostEnvelope top-level keys

`host_id` (MAC, primary key), `oui_vendor`, `ip_observations[]`, `first_seen`,
`last_seen`, `ethernet`, `pipeline_1`, `pipeline_2`, `pipeline_3`, `triage`,
`lm_envelope`.

Pipeline blocks are **absent** (not null) when not fired. Each protocol
sub-block carries a `deterministic_label` / `deterministic_confidence` /
`candidate_labels` triplet. `candidate_labels` is non-empty only on a
deterministic miss — it is the only thing `NormalizeSignal` sees.

### Triage routing (first match wins)

```
signal_count == 0                                              → SKIP
signal_count == 1 and not floor_triggers                       → STAMP_LOW
consensus.confidence == HIGH and not ambiguous and not contra  → DETERMINISTIC_FINAL
ambiguous and not fusion_needed                                → ENQUEUE_NORMALIZE
ambiguous and fusion_needed                                    → ENQUEUE_FULL
else                                                           → ENQUEUE_FUSION
```

After NORMALIZE completes, **re-run routing** — hosts can upgrade to
`DETERMINISTIC_FINAL` when the last ambiguity resolves.

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

### FusionOutput fields

`host_id`, `mac`, `ip`, `path` (DETERMINISTIC_FINAL | NORMALIZED_FINAL | FUSED | FUSED_RLM | STAMP_LOW), `device_class`, `confidence`, `reasoning_trace`, `open_questions[]`, `contradiction` (bool), `contradictions[]`.

### InventoryRecord → envelope mapping (for `_to_cpe_*` and `_to_device_class`)

| Field | Source priority |
|-------|----------------|
| `hostname` | DHCP option 12 → LLMNR self-claim → SMB NTLMSSP `MsvAvNbComputerName`/`workstation` → mDNS A |
| `vendor` (CPE slug) | DICOM manufacturer/impl_uid → WS-D prefix → DHCP VCI → OUI |
| `product` (CPE slug) | DICOM model/impl_uid → DHCP VCI → WS-D series code |
| `device_class` | DICOM Modality (CT/MR/US/etc.) → WS-D series → DHCP role → heuristic |
| `version` | DICOM `(0018,1020)` → mDNS TXT firmware key |

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

## DSPy Signatures (do not change field names without recompiling)

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

## Refactor Milestones (current state: monolith)

The working code lives in `poc_agentic_passive_device_identification.py` (~4000 lines). The target layout above is the destination. Migration is milestone-gated:

- **M0** done when: `just agent-no-llm` works, `models.toml` exists, artifact dirs gitignored.
- **M1** done when: `mdt` entry point installed; monolith wrapped as `_monolith.py`.
- **M2** done when: pydantic v2 envelope in `schemas/`; `core/` extracted.
- **M3** done when: `mdt parse pcap/x.pcap | jq .` yields one envelope per line.
- **M4** done when: `mdt parse … | mdt agent --no-llm` matches monolith output; `agent/config.py` owns model loading.
- **M5** done when: Jinja template renders identical report (golden test).
- **M6** done when: `just fixture` works via `mdt-fixtures`.
- **M7** done when: monolith and legacy `.txt` arch docs deleted; tests green.

When working on any milestone, verify the **exit criterion** before marking complete. Do not skip milestones.

---

## What NOT to Do

- Do not add retry loops to `NormalizeSignal` calls. Fix the training set.
- Do not import `dspy` or `pyshark` in `parser/`. `parser/` is LM-free.
- Do not import `parser/` from `agent/`.
- Do not put model strings (`ollama_chat/...`) anywhere except `models.toml` and `agent/config.py`.
- Do not add `__init__.py` logic that imports across domain boundaries.
- Do not call `dspy.configure(lm=...)` outside of `agent/` initialization.
- Do not pass raw PHI (PID-3/5/7/8, DICOM (0010,*) tags) to any LM call.
- Do not add `null`/empty pipeline blocks to the envelope — absent means not fired.
- Do not key host state on IP address; always key on MAC (`host_id`).
- Do not write code that sends packets or resolves observed hostnames via DNS.
