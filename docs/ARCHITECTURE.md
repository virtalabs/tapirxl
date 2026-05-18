# TapirXL — Architecture

| Field    | Value                                                                                 |
| -------- | ------------------------------------------------------------------------------------- |
| Document | Passive Medical Device Identification via Stacked Protocol Signal Fusion              |
| Version  | 3.0 — unified (supersedes `ARCHITECTURE.txt` v1.0 + `PROPOSED_ARCHITECTURE.txt` v2.0) |
| Date     | 2026-05-14                                                                            |
| Status   | Authoritative                                                                         |

---

## §0 — Document History

Merges v1.0 and v2.0 plus the packaging refactor. v2.0 superseded v1.0's §1–3,
§6, §7, §10, §11, §14; v1.0 §5 (OUI), §8 (Fusion), §9 (DSPy compile), §12
(Output), §13 (Limitations) carry forward. v3.0 adds: packaging stack (uv /
ruff / just / Python 3.14), `src/tapirxl/` layout, Jinja markdown template,
explicit `reports/` + `agents/` artifact dirs, ports-as-Protocols for the
future parser↔agent split, and `models.toml` for model selection.

---

## §1 — System Overview

### 1.1 Objective

Passively identify and classify medical-network devices by fusing PCAP signals
into a canonical per-MAC JSON envelope, then classifying each host
deterministically when possible and via a chain-of-thought LM only when the
deterministic path does not converge.

### 1.2 Three concurrent pipelines

| #   | Name                  | Fires on                                                   | Latency       |
| --- | --------------------- | ---------------------------------------------------------- | ------------- |
| 1   | Broadcast / multicast | WS-Discovery, mDNS, DNS-SD, LLMNR, SSDP, ARP, Capsule-MDIP | < 60 s        |
| 2   | Session / passive OS  | TCP SYN, TLS Hello, SMB2 Negotiate, Kerberos, DNS, SSH     | first connect |
| 3   | Event-driven DPI      | DICOM, DHCP, HL7 MLLP, SNMP                                | event-bound   |

All three pipelines write into the same per-MAC envelope (§3.2). Block presence
**is** the signal; missing blocks are absent, not null.

### 1.3 Constraints

- PCAP file input, read-only, offline. Live capture deferred.
- No active probing, no packet injection, no DNS lookups against observed names.
- All LM inference local via Ollama; no external APIs.
- No custom training. Off-the-shelf instruction models.
- Target hardware: Apple M2 Max 32 GB.

### 1.4 Output

- Default: markdown asset inventory in `reports/`, rendered from
  `templates/report_template.md.jinja` via `jinja-markdown2`. One record per
  MAC: IP observations, hostname (source-labeled), device class, confidence
  (HIGH/MEDIUM/LOW), pipelines fired, reasoning trace, open questions,
  contradictions, expert flags.
- `--json`: one `InventoryRecord` JSONL per host on stdout, conforming to
  `schemas/inventory_record.schema.json`. This is the wire format for the
  future parser↔agent split (§16).

---

## §2 — Packaging Stack

### 2.1 Toolchain

| Tool           | Version | Role                                       |
| -------------- | ------- | ------------------------------------------ |
| Python         | 3.14    | runtime                                    |
| uv             | latest  | resolver + venv + lockfile                 |
| ruff           | latest  | linter + formatter                         |
| just           | latest  | task runner (https://just.systems/man/en/) |
| pyproject.toml | PEP 621 | single source of project metadata          |

### 2.2 Python deps

`pyshark`, `dspy-ai>=2.4`, `ollama`, `jinja2`, `jinja-markdown2`, `pydantic>=2`,
`typer`. Dev: `ruff`, `pytest`, `pytest-cov`, `mypy`.

### 2.3 System deps

`tshark` (PATH), `wireshark-common` (OUI db), `ollama` server, `deno` (only for
`--rlm` mode).

### 2.4 Model defaults

Selection is config-driven (`models.toml`, §2.9). Defaults below.

| Slot              | Default                     | Footprint | Role                                 |
| ----------------- | --------------------------- | --------- | ------------------------------------ |
| `lm`              | `deepseek-r1:14b` Q4_K_M    | 8.5 GB    | fusion CoT / RLM orchestrator        |
| `sub_lm`          | `qwen2.5-coder:3b` Q4_K_M   | 2.0 GB    | pick-from-N normalize; RLM sub-calls |
| `sub_lm.fallback` | `qwen2.5-coder:1.5b` Q4_K_M | 1.0 GB    | speed > rigor                        |

Memory budget (32 GB, defaults): 8.5 + 2.0 + KV 3.5 + buffers 1.5 + macOS 7.0
= 22.5 GB; headroom 9.5 GB. Safe.

### 2.5 Static data (version-controlled)

`static/ieee_oui.txt`, `fingerbank_dhcp_55.json`, `dicom_impl_uid_arcs.json`,
`hl7_sending_apps.json`, `snmp_sysobjectid_arcs.json`.

### 2.6 Artifact directories (gitignored)

`pcap/` (input), `reports/` (md output), `agents/` (compiled DSPy modules:
`compiled_fusion.json`, `compiled_normalize.json`).

### 2.7 `justfile` recipes

`install`, `fmt`, `lint`, `test`, `typecheck`, `fixture`, `parse PCAP`,
`agent PCAP`, `agent-json PCAP`, `agent-no-llm PCAP`, `compile-fusion`,
`compile-normalize`.

### 2.8 `pyproject.toml` essentials

```toml
[project]
name = "tapirxl"
version = "0.3.0"
requires-python = ">=3.14"
dependencies = ["pyshark", "dspy-ai>=2.4", "ollama", "jinja2",
                "jinja-markdown2", "pydantic>=2", "typer"]

[project.scripts]
tapirxl          = "tapirxl.cli:app"
tapirxl-parse    = "tapirxl.parser.cli:main"
tapirxl-agent    = "tapirxl.agent.cli:main"
tapirxl-fixtures = "tapirxl.fixtures.cli:main"

[dependency-groups]
dev = ["ruff", "pytest", "pytest-cov", "mypy"]

[tool.ruff]
target-version = "py314"
line-length = 100
[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "RUF"]
```

### 2.9 `models.toml`

Two slots mirror dspy: `lm` (fusion / RLM orchestrator) and `sub_lm`
(normalize, **and** `sub_lm=` for `dspy.RLM` so `llm_query` sub-calls route to
the smaller model).

```toml
[provider]
name     = "ollama"            # future: "openai", "anthropic"
endpoint = "http://localhost:11434"

[lm]
model          = "ollama_chat/deepseek-r1:14b"
context_window = 8192
max_tokens     = 1024
temperature    = 0.2

[sub_lm]
model          = "ollama_chat/qwen2.5-coder:3b"
context_window = 32768
max_tokens     = 128
temperature    = 0.0

[sub_lm.fallback]
model          = "ollama_chat/qwen2.5-coder:1.5b"
context_window = 32768
max_tokens     = 128
temperature    = 0.0

[compile]
lm_max_tokens     = 2000
sub_lm_max_tokens = 128
```

**Resolution order:** CLI (`--lm` / `--sub-lm` / `--models PATH`) → env
`TAPIRXL_MODELS` → `./models.toml` → packaged default. Loaded by
`tapirxl/agent/config.py:load_model_config(path) -> ModelConfig`; domain code
receives the resolved `ModelConfig`. Only `agent/adapters/ollama_lm.py`
constructs `dspy.LM`.

---

## §3 — Data Schemas

The envelope is the contract. Adding fields is non-breaking; renaming or
removing fields invalidates compiled DSPy modules and inventory consumers.

### 3.1 SignalObservation — internal per-packet record

| Field                           | Type        | Notes                                                                                                                                                           |
| ------------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pipeline`                      | 1 \| 2 \| 3 |                                                                                                                                                                 |
| `protocol`                      | enum        | WS_DISCOVERY, MDNS_A/TXT, DNS_SD, LLMNR, SSDP, CAPSULE_MDIP, ARP, TCP_SYN, TLS_SNI, SMB2, KERBEROS, DNS, SSH, DICOM_ASSOC, DICOM_PDATA, DHCP, HL7, SNMP, EXPERT |
| `src_mac`                       | str         | lowercase colon-delim                                                                                                                                           |
| `src_ip`, `dst_ip`              | str \| None |                                                                                                                                                                 |
| `timestamp`                     | float       | Unix epoch                                                                                                                                                      |
| `fields`                        | dict        | protocol-specific (§4)                                                                                                                                          |
| `expert_flag`, `expert_message` | bool, str   |                                                                                                                                                                 |

### 3.2 HostEnvelope — canonical, per-MAC

Primary key: `host_id` (MAC). Top-level keys: `host_id`, `oui_vendor`,
`ip_observations`, `first_seen`, `last_seen`, `ethernet`, `pipeline_1`,
`pipeline_2`, `pipeline_3`, `triage`, `lm_envelope`. Pipeline blocks are
**absent** when not fired.

`ethernet`: `mac`, `oui_vendor`, `is_locally_administered`,
`ttl_observations`.

### 3.3 Pipeline 1 block (broadcast / multicast)

Optional sub-blocks: `ws_discovery`, `mdns`, `ssdp`, `llmnr`, `capsule_mdip`.

`ws_discovery` carries `uuid`, `vendor_prefix_hex` (e.g. `5048`),
`vendor_prefix_ascii` (`PH`), `series_code_hex`, `series_code_ascii`,
`types`, `scopes`, `app_sequence_instance_id`, `deterministic_label`,
`deterministic_confidence`, `candidate_labels`.

`mdns` carries `hostname`, `txt_parsed`, `txt_raw`, `dns_sd_services`,
`ptr_records`, `spoof_check` (`mac_locally_administered`,
`oui_matches_advertised_mfg`, `spoof_suspected`), and the same
`deterministic_*` triplet.

`ssdp`: `server_header`, `usn`, `nt`, `location_url`, `nts`, `deterministic_*`.
`llmnr`: `queries_emitted`, `claimed_hostname`, `hostname_pattern_match`.
`capsule_mdip`: `udp_5090_present`, `apdu_client_token`, `session_rate_hz`,
`peer_ip`, `tls_tcp_5090`, `deterministic_*`.

Each sub-block uses the same `deterministic_label` / `deterministic_confidence`
/ `candidate_labels` triplet — `candidate_labels` is populated only on
deterministic miss and is what NormalizeSignal sees.

### 3.4 Pipeline 2 block (session / passive OS)

Sub-blocks: `tcp_syn_fingerprint` (`ttl`, `mss`, `window_scale`, `sack_perm`,
`timestamp_option`, deterministic triplet), `tls_sni` (`sni_domains`,
`ja3_client`, `ja3s_server`, `ecosystem_hints`, deterministic triplet),
`smb2` (`dialects_offered`, `dialect_negotiated`, `signing_required`,
optional `ntlmssp` {`target_computer`, `workstation`, `domain`}),
`kerberos` (`realm`, `cname_observed`), `dns` (`queries`, `responses`,
`vendor_domain_hits`), `ssh` (`banner`, `kex_algorithms`).

### 3.5 Pipeline 3 block (event-driven DPI)

`dicom_association[]` per association observed: `implementation_class_uid`,
`impl_class_uid_vendor_arc`, `implementation_version_name`,
`ae_titles_calling`, `ae_titles_called`, `sop_classes_negotiated`,
`transfer_syntaxes`, `image_uid_arc_counts`, `pdu_type_byte`, `tags` block
(DICOM `(0008,0070)` Manufacturer, `(0008,1090)` Model, `(0018,1020)` SW
versions, `(0018,1000)` Serial, `(0008,0060)` Modality, `(0008,0080)`
Institution), `deterministic_*`.

`dhcp[]`: `events`, `option60_vendor_class`, `option12_hostname`,
`param_request_list`, `fingerbank_dhcp_hit`, `lease_yiaddr`, `deterministic_*`.

`hl7[]`: `mllp_detected`, `sending_app`, `receiving_app`, `message_types`,
`version`, `interface_endpoint`, `deterministic_*` (PHI redacted — §4.4.3).

`snmp[]`: `version`, `community`, `sys_descr`, `sys_name`, `sys_object_id`,
`deterministic_*`.

### 3.6 Triage block

`signal_count`, `pipelines_fired`, `floor_triggers`, `expert_flags`,
`deterministic_consensus` (`device_class`, `confidence`,
`supporting_pipelines`, `supporting_signals`),
`deterministic_contradictions`, `contradiction_codes`, `routing`.

Routing:

| Value                 | Meaning                                                    |
| --------------------- | ---------------------------------------------------------- |
| `DETERMINISTIC_FINAL` | all required fields resolved deterministically; LM skipped |
| `SKIP`                | `signal_count == 0`                                        |
| `STAMP_LOW`           | one signal, no floor triggers; no LM                       |
| `ENQUEUE_NORMALIZE`   | ambiguous fields exist; LM normalize then re-evaluate      |
| `ENQUEUE_FUSION`      | multi-signal but no deterministic consensus                |
| `ENQUEUE_FULL`        | both normalize and fusion required                         |

### 3.7 LM envelope block

`lm_envelope.ambiguous_fields[]`: each entry has `raw_value`, `source_protocol`,
`source_pipeline`, `field_path` (JSON pointer), `candidate_labels`,
`host_context` (vendor/series hints, clinical_service_hit,
pipeline_3_dicom_vendor). This is the **only** thing NormalizeSignal sees;
each entry is a self-contained pick-from-N task. Empty list ⇒ NORM not invoked.

`lm_envelope.fusion_envelope` summary: `deterministic_consensus`,
`ambiguous_field_count`, `signal_count`, `pipelines_fired`, `floor_triggers`.

### 3.8 FusionOutput

`host_id`, `mac`, `ip`, `path` (`DETERMINISTIC_FINAL` | `NORMALIZED_FINAL` |
`FUSED` | `FUSED_RLM` | `STAMP_LOW`), `device_class`, `confidence`
(HIGH/MEDIUM/LOW), `reasoning_trace`, `open_questions`, `contradiction`,
`contradictions`.

### 3.9 InventoryRecord

Public wire format, bound to `schemas/inventory_record.schema.json`. Enums for
`vendor`, `product`, `device_class` line up with cpedict slugs so an upstream
CVE/CPE binder interpolates them into `cpe:2.3:` strings directly. Mapping
back to the envelope is in §12.2.

---

## §4 — Protocol Field Extraction

### 4.1 Display filter (single pass)

```text
udp.port==3702 or udp.port==5353 or udp.port==5355 or udp.port==1900 or
udp.port==5090 or arp                                              # P1
or (tcp.flags.syn==1 and tcp.flags.ack==0) or tls.handshake.type==1
or smb2.cmd==0 or kerberos or dns
or (tcp.port==22 and tcp.payload contains "SSH-")                  # P2
or (tcp.port==104 or tcp.port==2104 or tcp.port==2762)
or bootp or (tcp contains "MSH|") or snmp                          # P3
or _ws.expert
```

HL7 dissection cross-checks `tcp.payload[0] == 0x0B` to reject FP heuristic
hits.

### 4.2 Pipeline 1

| Protocol     | Key fields                                                       | Notes                                                                                       |
| ------------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| WS-Discovery | UUID regex, `wsa:Types`, `wsd:Scopes`, `AppSequence/@InstanceId` | UUID[0:4] hex → ASCII vendor prefix (`5048`=PH); UUID[4:8] → series code (`BH`, `BV`, `GD`) |
| mDNS A / TXT | `dns.resp_name`, `dns.a`, `dns.txt`                              | spoof check: locally-administered bit ∧ ¬(OUI vendor LIKE TXT mfg)                          |
| DNS-SD PTR   | `dns.ptr_domain_name`                                            | `_dicom._tcp` / `_hl7._tcp` / `_fhir._tcp` ⇒ `CLINICAL_SERVICE` floor trigger               |
| LLMNR        | `llmnr.dns_qry_name`, `llmnr.dns_resp_name`                      | self-claim hostname                                                                         |
| SSDP         | UDP/1900 payload                                                 | parse HTTP-like headers (`NT`, `USN`, `ST`, `SERVER`, `LOCATION`, `NTS`)                    |
| Capsule MDIP | UDP/5090 `APDUclnt.0-…`                                          | extract UUID, port, sequence; track session rate Hz                                         |
| ARP          | `arp.opcode`, `arp.src.proto_ipv4`, `arp.src.hw_mac`             | MAC↔IP binding; gratuitous ARP flagged                                                      |

### 4.3 Pipeline 2

| Protocol | Key fields                                                                                          |
| -------- | --------------------------------------------------------------------------------------------------- |
| TCP SYN  | `ip.ttl`, `tcp.window_size`, MSS, WScale, SACK, Timestamps                                          |
| TLS SNI  | `tls.handshake.extensions_server_name`; ecosystem hints via prefix match                            |
| SMB2     | dialects offered/negotiated, signing required, NTLMSSP `target_computer` / `workstation` / `domain` |
| Kerberos | `kerberos.realm`, `kerberos.cname.name_string`                                                      |
| DNS      | queries, responses, vendor-domain hits                                                              |
| SSH      | banner, KEX algorithms                                                                              |

TCP SYN deterministic table (subset): `TTL=128,MSS=1460,WScale=8,SACK=true` →
Win10/11; `TTL=64,WScale=7,SACK+TS` → recent Linux; `TTL=64,MSS=1460,WScale=6,TS`
→ macOS 12+; `TTL=255` → iOS/Cisco/embedded; `TTL=128,MSS=512-536` → medical
(rare).

TLS SNI hints: `*.sentinelone.net` → `sentinelone_edr`;
`*.events.data.microsoft.com` → `windows_telemetry`;
`*.do.dsp.mp.microsoft.com` → `windows_delivery_optimization`;
`*.teamviewer.com` → `teamviewer_client`; `*.fhir.*` → `fhir_server`.

SMB2 dialect → OS: `0x0311`=Win10/2016+; `0x0302`=Win8.1/2012R2;
`0x0300`=Win8/2012; `0x0210`=Win7/2008R2; `0x0202`=Vista/2008.

### 4.4 Pipeline 3

**DICOM** (no dissector required for core fields): byte 0 = `0x01` (A-ASSOC-RQ)
/ `0x02` (-AC) / `0x04` (P-DATA-TF). Compute IP+TCP header lengths; PDU starts
at offset. AE titles at PDU 10–25 (Called) / 26–41 (Calling). User-Info sub-
items at PDU 74+: type `0x52` = Implementation Class UID, type `0x55` =
Implementation Version Name. Presentation Context (type `0x20`) holds Abstract
Syntax (`0x30`) with SOP class UID.

Vendor-arc match (`static/dicom_impl_uid_arcs.json`):

| Arc                    | Vendor                                  |
| ---------------------- | --------------------------------------- |
| `1.3.46.670589.30.`    | Philips Eleva platform                  |
| `1.3.46.670589.40.`    | Philips Clinical Collaboration Platform |
| `1.3.46.`              | Philips Healthcare                      |
| `1.3.12.2.1107.`       | Siemens Healthineers                    |
| `1.2.840.113619.`      | GE Healthcare                           |
| `1.2.276.0.7230010.3.` | OFFIS DCMTK                             |

P-DATA scan for Philips image UID arc `1.2.840.113704.`; hits surfaced in
`image_uid_arc_counts`. When dissector available, also pull `(0008,0070)`,
`(0008,1090)`, `(0018,1020)`, `(0018,1000)`, `(0008,0060)` Modality (`CT`,
`MR`, `US`, `CR`, `DX`, `MG`, `NM`, `PT`), `(0008,0080)`.

**DHCP**: `bootp.option.dhcp` → DISCOVER/REQUEST/ACK; `option.hostname` (12);
`option.vendor_class_id` (60); `request_list_item` (55) — concat as PRL
signature, look up in `fingerbank_dhcp_55.json`. Vendor-class label table
(subset): `Philips IntelliVue`, `Natus`, `Spacelabs`, `CapsuleTech`,
`MSFT 5.0`, `android-dhcp-*`.

**HL7 MLLP**: require `tcp.payload[0]==0x0B`; strip leading `0x0B` and trailing
`0x1C 0x0D`; split segments on `0x0D`; first must be `MSH`. Pull MSH-3/4/5/9/12.
Track endpoint per `(src_ip:port, dst_ip:port)`. **PHI redaction is mandatory
pre-envelope**: PID-3/5/7/8 and DICOM `(0010,*)` replaced with `<PHI>`.
Institution `(0008,0080)` retained.

**SNMP**: pull `1.3.6.1.2.1.1.{1.0,2.0,5.0}` (sysDescr, sysObjectID, sysName).
sysDescr prefix → label: `Cisco IOS Software` → Cisco; `Linux …` → Linux;
`Philips Medical` → Philips medical; `HP-` → HP printer.

### 4.5 Expert info

`_ws.expert` severity ≥ 4 pushes an `EXPERT` observation; message appended to
`triage.expert_flags`.

---

## §5 — OUI Lookup

`static/ieee_oui.txt` is the source. A curated `OUI_FALLBACK` supplements it
with medical / hypervisor / network-vendor OUIs the IEEE table sometimes omits
(Philips Healthcare PCCI, Draeger, GE Medical, Siemens Healthineers, Spacelabs,
VMware, Hyper-V, Palo Alto). Lookup key is uppercase first three octets joined
by colons (`AA:BB:CC`). The free-form vendor string is mapped to a canonical
cpe:2.3 vendor slug at output time via `core/enums.py:CPE_VENDOR_OUI_MAP`.

---

## §6 — Triage Gate

### 6.1 Routing (first match wins)

```
signal_count == 0                                              → SKIP
signal_count == 1 and not floor_triggers                       → STAMP_LOW
consensus.confidence == HIGH and not ambiguous and not contra  → DETERMINISTIC_FINAL
ambiguous and not fusion_needed                                → ENQUEUE_NORMALIZE
ambiguous and fusion_needed                                    → ENQUEUE_FULL
else                                                           → ENQUEUE_FUSION
```

After NORMALIZE completes, **re-run** routing — hosts can upgrade
`ENQUEUE_FULL` → `DETERMINISTIC_FINAL` when the last ambiguity resolves.

### 6.2 Floor triggers

| Code                        | Pipeline | Condition                                                             |
| --------------------------- | -------- | --------------------------------------------------------------------- |
| `MEDICAL_UUID_PREFIX`       | P1       | `ws_vendor_prefix_hex` ∈ {`5048`, `4745`, `5349`, `4452`, `4243`}     |
| `CLINICAL_SERVICE`          | P1       | `dns_sd_services` contains `_dicom._tcp` / `_hl7._tcp` / `_fhir._tcp` |
| `EXPERT_ANOMALY`            | \*       | `expert_flags` non-empty                                              |
| `DICOM_VENDOR_ARC`          | P3       | `impl_class_uid_vendor_arc` in known set                              |
| `DICOM_PHILIPS_IMAGE_UID`   | P3       | `image_uid_arc_counts["1.2.840.113704."] > 0`                         |
| `DHCP_MEDICAL_VENDOR_CLASS` | P3       | DHCP option-60 matches medical list                                   |
| `HL7_CLINICAL_INTERFACE`    | P3       | `hl7.mllp_detected`                                                   |
| `SNMP_MEDICAL_SYSDESCR`     | P3       | SNMP sysDescr matches medical prefix                                  |

### 6.3 Cross-pipeline contradiction codes

| Code                                     | Condition                                          | Effect                                          |
| ---------------------------------------- | -------------------------------------------------- | ----------------------------------------------- |
| `C1 OUI_DICOM_VENDOR_MISMATCH`           | OUI vendor ≠ DICOM manufacturer                    | flag; often benign (VMware OUI on Philips host) |
| `C2 MDNS_SPOOF_SUSPECTED`                | mDNS spoof check tripped                           | cap final confidence at MEDIUM                  |
| `C3 PHILIPS_WSDISC_VS_NON_PHILIPS_DICOM` | WS-D prefix `PH` + DICOM arc ≠ `1.3.46.`           | flag for investigation                          |
| `C4 DOMAIN_HOSTNAME_MISMATCH`            | Kerberos realm present + LLMNR claim out-of-domain | log only                                        |

### 6.4 Deterministic consensus

Collect `deterministic_label` values across pipelines where confidence is HIGH.
If all agree or are **subsumption-compatible** (e.g. `Philips IntelliVue
MX700/MX800` subsumes `Philips IntelliVue patient monitor`), pick the
most-specific as `consensus.device_class` with HIGH and record
`supporting_pipelines` / `supporting_signals`. Disagreement → MEDIUM and labels
recorded in `deterministic_contradictions`.

---

## §7 — Normalization Tier (Layer 4)

- Model: `[sub_lm]` from `models.toml` (default `qwen2.5-coder:3b`).
- DSPy: `dspy.Predict` (no ChainOfThought). Pick-from-N, not generation.
- Trigger: only for `ENQUEUE_NORMALIZE` / `ENQUEUE_FULL`.
- Input: one `ambiguous_fields[]` entry plus a sanitized envelope context.

### 7.1 Signature

```python
class NormalizeSignal(dspy.Signature):
    """Pick verbatim normalization for one ambiguous device-protocol field.
    OUTPUT RULES (binding):
      1. normalized_value MUST be verbatim from candidate_labels when one matches.
      2. Otherwise output 'OTHER:<short sanitized reason>' and set confidence='LOW'.
      3. Use host_context as decision support — facts that constrain the answer.
    """
    ambiguous_field_bundle: str = dspy.InputField()   # one ambiguous_fields[] entry as JSON
    envelope_context:       str = dspy.InputField()   # PHI-redacted envelope snippet
    normalized_value:       str = dspy.OutputField()  # verbatim candidate OR 'OTHER:…'
    confidence:             str = dspy.OutputField()  # HIGH | MEDIUM | LOW
```

### 7.2 Invocation & throughput

For each `ENQUEUE_NORMALIZE` / `ENQUEUE_FULL` host, and each entry in
`row.lm_envelope.ambiguous_fields`, call `NormModule` and write result back at
`entry.field_path`. Re-run §6.1 after all entries resolved.

Throughput (M2 Max): qwen2.5-coder:3b ~100–140 tok/s; 200-in/30-out ≈ 2 s;
0–3 ambiguous fields per host ⇒ 0–6 s normalize budget per host.

### 7.3 Verbatim rule (load-bearing)

`normalized_value` is checked post-hoc against `candidate_labels`. Non-matching
outputs are rejected; the field is left ambiguous and confidence is downgraded
to MEDIUM at most. **No retries.** Fix model behavior with better compile-time
examples (§9), not retry loops.

---

## §8 — Fusion Tier (Layer 5)

- Model: `[lm]` from `models.toml` (default `deepseek-r1:14b`).
- DSPy: `dspy.ChainOfThought` (default) or `dspy.RLM` (`--rlm`).
- Trigger: `ENQUEUE_FUSION` / `ENQUEUE_FULL` not resolved by post-normalize re-triage.

`FuseSignals.signal_register` is the **full v3.0 envelope** serialized as JSON,
PHI-redacted, internal fields stripped. The envelope already carries
`triage.deterministic_consensus` and `triage.deterministic_contradictions`.

`FuseSignalsRLM` collapses `ContradictSignals` + `FuseSignals` into one REPL-
driven call. The RLM is built with `sub_lm = <[sub_lm] from models.toml>` so
inline `llm_query` sub-calls route to the smaller model.

### Confidence rules (binding)

- **HIGH**: 3+ independent signals agree ∧ no contradictions, OR 2+ agree ∧
  floor trigger ∧ no contradictions.
- **MEDIUM**: 2 signals, OR 1 signal + floor trigger, OR contradiction (caps
  at MEDIUM regardless of signal_count).
- **LOW**: 1 signal, no floor trigger.

Cross-pipeline contradictions are mostly benign (VMware OUI on virtualized
DICOM gateway). Triage caps confidence but does **not** auto-fail; fusion's
reasoning trace MUST cite the contradiction explicitly when present.

---

## §9 — DSPy Compilation

| File                             | Module                              | Metric                                                        |
| -------------------------------- | ----------------------------------- | ------------------------------------------------------------- |
| `agents/compiled_normalize.json` | `NormalizeSignal`                   | exact_match on `normalized_value`                             |
| `agents/compiled_fusion.json`    | `FuseSignals` + `ContradictSignals` | exact_match on `confidence` + partial_match on `device_class` |

Training examples: `agent/compile/training_normalize.py` and
`agent/compile/training_fusion.py`. Compilation is offline, one-time per
signature change. Load at runtime; never recompile per run.

### Normalize training set (sketch)

| #   | raw_value                                 | source       | candidates                                                          | expected                           | conf |
| --- | ----------------------------------------- | ------------ | ------------------------------------------------------------------- | ---------------------------------- | ---- |
| 1   | `urn:ihe-pcd:device:patientmonitor`       | WS_DISCOVERY | IHE PCD; Philips IntelliVue; Generic; OTHER                         | Philips IntelliVue patient monitor | HIGH |
| 2   | `vendor:CustomCorp`                       | MDNS_TXT     | Generic UPnP; Unknown medical; OTHER                                | `OTHER:CustomCorp custom device`   | LOW  |
| 3   | `1.3.46.670589.30.36.0`                   | DICOM_ASSOC  | Philips Eleva; Philips Healthcare; Generic DICOM; OTHER             | Philips Eleva platform             | HIGH |
| 4   | `Spacelabs Healthcare`                    | DHCP         | Spacelabs patient monitor; Generic medical; OTHER                   | Spacelabs patient monitor          | HIGH |
| 5   | `Linux UPnP/1.0 Sonos/94.1-75110 (ZPS39)` | SSDP         | Sonos ZPS39 fw 94.1-75110; Generic Sonos; Generic Linux UPnP; OTHER | Sonos ZPS39 firmware 94.1-75110    | HIGH |

---

## §10 — Model Configuration

Driven by `models.toml` (§2.9). Resolved values shape `dspy.LM` construction in
`tapirxl/agent/config.py`:

```python
lm     = dspy.LM(cfg.lm.model,     temperature=cfg.lm.temperature,
                 max_tokens=cfg.lm.max_tokens, num_ctx=cfg.lm.context_window)
sub_lm = dspy.LM(cfg.sub_lm.model, temperature=cfg.sub_lm.temperature,
                 max_tokens=cfg.sub_lm.max_tokens, num_ctx=cfg.sub_lm.context_window)
dspy.configure(lm=lm)                        # top-level FuseSignals CoT
norm_module = NormModule()                   # bound to sub_lm via dspy.context
fuse_rlm    = FuseModuleRLM(sub_lm=sub_lm)   # llm_query sub-calls hit sub_lm
```

Per-host wall-clock (M2 Max, Q4_K_M, defaults): DETERMINISTIC_FINAL <50 ms (no
LM); normalize-only 2–6 s; fusion-only 30–60 s; normalize+fusion 32–66 s.

Expected distribution (Schoolcraft 59-min PCAP): DETERMINISTIC_FINAL 60–70 %;
normalize-only 15–20 %; fusion-only 10–15 %; both 5–10 %.

Total wall-clock estimate (60 broadcast-active hosts): v1.0 (all hosts through
both tiers) 27–88 min; v3.0 (deterministic-first + 3B norm) 9–22 min.

---

## §11 — Execution Flow

### 11.1 Pre-flight (abort on any failure)

1. `tshark` on PATH.
2. `models.toml` resolves and parses (CLI → env → CWD → packaged).
3. Ollama (`[provider].endpoint`) reachable (skip if `--no-llm` / `--compile-*`).
4. Resolved `[sub_lm].model` present in Ollama (skip if `--no-llm` / fusion-only compile).
5. Resolved `[lm].model` present in Ollama (skip if `--no-llm` / normalize-only compile).
6. `static/ieee_oui.txt`, `fingerbank_dhcp_55.json`, `dicom_impl_uid_arcs.json` readable.
7. `agents/compiled_normalize.json` / `agents/compiled_fusion.json` present (or `--compile-*` set).
8. Input PCAP exists and is readable (skip if compile-only).

### 11.2 Pipeline steps

| Step | Layer        | Module                                                                      | Action                                                                                                        |
| ---- | ------------ | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 1    | bootstrap    | `core/oui.py`, `parser/tables.py`                                           | load OUI + Fingerbank + DICOM + HL7 + SNMP tables                                                             |
| 2    | bootstrap    | `agent/modules/*.py`                                                        | load `compiled_normalize.json`, `compiled_fusion.json`                                                        |
| 3    | L1 extract   | `parser/pipeline.py` + `parser/extractors/*`                                | single sweep; dispatch by pipeline; write `SignalObservation`s                                                |
| 4    | L2 envelope  | `parser/envelope_builder.py`                                                | merge into per-MAC `HostEnvelope`; spoof check; finalize timestamps                                           |
| 5    | L3 triage    | `parser/deterministic.py` + `parser/triage.py`                              | per-pipeline labelers; consensus; contradictions; ambiguous fields; route                                     |
| 6    | L4 normalize | `agent/normalize.py`                                                        | per `ENQUEUE_NORMALIZE` / `ENQUEUE_FULL`: `NormModule` per ambiguous field; write back; re-triage             |
| 7    | L5 fusion    | `agent/fusion.py`                                                           | per `ENQUEUE_FUSION` / `ENQUEUE_FULL`: `ContradictSignals` + `FuseSignals` (or `FuseSignalsRLM` with `--rlm`) |
| 8    | L6 output    | `agent/inventory.py` + `agent/adapters/markdown_sink.py` \| `jsonl_sink.py` | merge routes; sort by confidence then IP; render template or emit JSONL                                       |

### 11.3 CLI

```bash
# Today (transitional, single binary)
tapirxl agent <pcap>                  # full pipeline → reports/
tapirxl agent <pcap> --no-llm         # triage only, no Ollama
tapirxl agent <pcap> --json           # full pipeline → JSONL on stdout
tapirxl agent <pcap> --rlm            # RLM fusion (experimental)
tapirxl agent --compile               # FuseSignals → agents/compiled_fusion.json
tapirxl agent --compile-normalize     # NormalizeSignal → agents/compiled_normalize.json
tapirxl agent <pcap> --filter H       # HIGH-confidence only in markdown
tapirxl agent <pcap> --models PATH    # alternate models.toml
tapirxl agent <pcap> --lm NAME        # override [lm].model
tapirxl agent <pcap> --sub-lm NAME    # override [sub_lm].model
tapirxl agent <pcap> --sub-lm-fallback # use [sub_lm.fallback]
tapirxl fixtures                      # regenerate synthetic Philips demo PCAP

# After domain split (§16) — same package, separate processes
tapirxl parse <pcap>                  # envelope JSONL on stdout
tapirxl parse <pcap> | tapirxl agent  # piped; agent reads stdin
```

---

## §12 — Output

### 12.1 Markdown via Jinja

Renderer: `jinja-markdown2`. Template: `templates/report_template.md.jinja`.
The current monolithic `_render_record` collapses to a thin view-model builder
(`agent/inventory.py:to_report_view`) plus the template. No business logic in
the template.

Sketch (header + per-record loop):

```jinja
# Asset Inventory — Stacked Protocol Signal Fusion

**Capture:** `{{ pcap.name }}`  **Date:** `{{ today }}`  **Mode:** {{ mode }}

| Category | Count |
|----------|-------|
| Total MAC hosts | {{ totals.hosts }} |
| SKIP / STAMP_LOW / DETERMINISTIC_FINAL / LM-queued |
  {{ totals.skipped }} / {{ totals.stamp_low }} / {{ totals.deterministic_final }} / {{ totals.lm_queued }} |

{% for r in records %}
## {{ r.ip }} — {{ r.device_class }}

| Field | Value |
|-------|-------|
| MAC | `{{ r.mac }}` |
| OUI Vendor | {{ r.oui_vendor }} |
| Hostname | {{ r.hostname or "—" }} |
| Vendor / Product (CPE) | `{{ r.cpe_vendor or "—" }}` / `{{ r.cpe_product or "—" }}` |
| Pipelines fired | {{ r.pipelines_fired | join(", ") }} |
| Triage routing | `{{ r.triage_routing }}` |
| Confidence | **{{ r.confidence }}** |

{% for p in r.pipelines %}
- **{{ p.name }}:** `{{ p.label or "—" }}` (**{{ p.confidence }}**)
{% endfor %}

{% if r.fusion %}
**Fusion reasoning:** {{ r.fusion.reasoning_trace }}
**Open questions:** {{ r.fusion.open_questions | join("; ") or "None" }}
{% endif %}

---
{% endfor %}
```

### 12.2 JSONL inventory mapping

| InventoryRecord field | Source in envelope                                                                                             |
| --------------------- | -------------------------------------------------------------------------------------------------------------- |
| `hostname`            | DHCP option 12 → LLMNR self-claim → SMB NTLMSSP `MsvAvNbComputerName`/`workstation` → mDNS A (first non-empty) |
| `ip_address`          | first of `ip_observations`                                                                                     |
| `mac_address`         | `host_id`                                                                                                      |
| `vendor`              | `core/enums.py:_to_cpe_vendor` — DICOM > WS-D > DHCP > OUI                                                     |
| `product`             | `core/enums.py:_to_cpe_product` — DICOM > DHCP > WS-D series                                                   |
| `version`             | DICOM `(0018,1020)` → mDNS TXT firmware key                                                                    |
| `device_class`        | `_to_device_class` — DICOM Modality > WS-D series → DHCP role → heuristic                                      |
| `open_ports`          | derived from `dns_sd_services` port map, WS-D (3702), mDNS (5353), LLMNR (5355), Capsule (5090), SSDP (1900)   |
| `confidence`          | post-fusion confidence; falls back to triage for `DETERMINISTIC_FINAL` / `STAMP_LOW`                           |

When `--json` is set, redirect `sys.stdout` → `sys.stderr` immediately after
argparse and keep the real stdout fd for JSONL only (third-party libs print
freely; the JSONL stream must stay clean).

---

## §13 — Known Limitations & Deferrals

**In scope (v3.0):** three-pipeline single-sweep extraction; per-MAC envelope;
deterministic-first classification; config-driven `[lm]` + `[sub_lm]`
(default `deepseek-r1:14b` + `qwen2.5-coder:3b`) via `models.toml`; compiled
DSPy modules for both tiers; cross-pipeline contradiction detection; PHI
redaction (HL7 PID + DICOM `(0010,*)`); markdown via Jinja; JSONL via stdout;
synthetic PCAP fixture generator.

**Deferred from v1.0:** IPI statistics (NFStream IpiPlugin); JA3/JA3S
fingerprinting; cross-capture drift; absence mapping; live capture.

**Deferred in v3.0:** continuous-live mode (envelope schema **is** the
persistence schema; only the I/O loop needs to change); envelope-delta
detection per MAC across windows; DICOM private tag parsing (Philips groups
2001/2005/200D); HL7 batch (BHS/BTS); SNMPv3 USM decryption.

---

## §14 — File Structure (target)

```
tapirxl/                                  ← git root
├── pyproject.toml
├── uv.lock
├── models.toml                           # §2.9
├── justfile
├── .python-version                       # 3.14
├── README.md
├── ARCHITECTURE.md                       # this document
├── pcap/                                 # input (gitignored)
├── reports/                              # md output (gitignored)
├── agents/                               # compiled DSPy modules (gitignored)
│   ├── compiled_fusion.json
│   └── compiled_normalize.json
├── schemas/
│   └── inventory_record.schema.json
├── templates/
│   └── report_template.md.jinja
├── static/
│   ├── ieee_oui.txt
│   ├── fingerbank_dhcp_55.json
│   ├── dicom_impl_uid_arcs.json
│   ├── hl7_sending_apps.json
│   └── snmp_sysobjectid_arcs.json
├── src/tapirxl/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                            # typer app
│   ├── core/                             # MAC, OUI, PHI redact, enums, IP sort, time
│   ├── schemas/                          # pydantic v2 models (envelope, inventory, fusion)
│   ├── parser/                           # FUTURE SERVICE 1 — deterministic, no LM
│   │   ├── cli.py                        # tapirxl-parse → envelope JSONL stdout
│   │   ├── pipeline.py                   # orchestrator
│   │   ├── envelope_builder.py
│   │   ├── deterministic.py              # per-pipeline labelers
│   │   ├── triage.py                     # consensus + contradictions + routing
│   │   ├── tables.py
│   │   ├── ports.py                      # PacketSource, EnvelopeSink protocols
│   │   ├── adapters/                     # pyshark_source, stdout_sink, rest_sink (future)
│   │   └── extractors/                   # one file per protocol (§4)
│   ├── agent/                            # FUTURE SERVICE 2 — LM tiers + reporting
│   │   ├── cli.py                        # tapirxl-agent
│   │   ├── config.py                     # models.toml → ModelConfig
│   │   ├── normalize.py / fusion.py / inventory.py
│   │   ├── ports.py                      # LMRunner, EnvelopeSource, InventorySink
│   │   ├── adapters/                     # ollama_lm, stdin_source, markdown_sink, jsonl_sink
│   │   ├── signatures/                   # NormalizeSignal, ContradictSignals, FuseSignals(RLM)
│   │   ├── modules/                      # NormModule, FuseModule, FuseModuleRLM
│   │   └── compile/                      # compile_*.py + training_*.py
│   └── fixtures/                         # synthetic PCAP generator
├── tests/
│   ├── unit/{parser,agent,core}/
│   ├── integration/test_end_to_end_synthetic.py
│   └── fixtures/synthetic_philips_demo.pcap
└── docs/                                 # narrative; no code
```

---

## §15 — Refactor Plan (monolith → packaged)

Each milestone is independently shippable.

**M0 — Toolchain bootstrap (no behavior change).** `uv init --package
--python 3.14`; ruff config; `justfile`; move `pcap/`, `reports/`, `agents/`
(holds `compiled_fusion.json`) into gitignored artifact dirs; move static data
under `static/`; **extract `NORM_MODEL` / `FUSE_MODEL` into `models.toml`**
(tomllib shim). Exit: `just agent-no-llm pcap/synthetic_philips_demo.pcap`
produces bit-identical output.

**M1 — `src/` layout.** Wrap the monolith verbatim as
`src/tapirxl/_monolith.py`. `cli.py` exposes the `tapirxl` typer app; subcommands
shell into monolith functions. Smoke test for synthetic PCAP. Legacy script
paths still work via shim.

**M2 — Schemas + core.** Move OUI loading, MAC normalize, PHI redaction, IP
sort, CPE enums into `core/`. Express envelope as pydantic v2 in
`schemas/envelope.py`. Keep dict-shaped `lm_serialize` output for DSPy.

**M3 — Parser subpackage.** Move each `_handle_*` extractor into
`parser/extractors/<protocol>.py`. Move `extract_packets`, envelope merging,
labelers, triage into `parser/{pipeline,envelope_builder,deterministic,triage,tables}.py`.
Define `parser/ports.py` (Protocols) and `adapters/{pyshark_source,stdout_sink}.py`.
Add `tapirxl parse <pcap>` subcommand. Exit: `tapirxl parse pcap/x.pcap | jq .` yields
one envelope per line.

**M4 — Agent subpackage.** Move signatures, modules, normalize/fusion
orchestrators, JSONL emitter, compile-mode. Promote the M0 `models.toml` shim
into `agent/config.py` (pydantic `ModelConfig`). Define `agent/ports.py` and
`adapters/{ollama_lm,stdin_source,markdown_sink,jsonl_sink}.py`. `ollama_lm.py`
is the only adapter that constructs `dspy.LM`. Exit: `tapirxl parse … | tapirxl agent
--no-llm` matches monolith output.

**M5 — Jinja template.** Extract `_render_record` + `write_inventory` into
`templates/report_template.md.jinja` and `to_report_view` in
`agent/inventory.py`; render via `jinja-markdown2`. Golden snapshot test.

**M6 — Fixtures subpackage.** Move `poc_traffic_generator.py` into
`src/tapirxl/fixtures/{topology,builder,cli}.py`. `just fixture` regenerates
the demo PCAP.

**M7 — Cleanup.** Drop monolith scripts. Drop `ARCHITECTURE.txt` and
`PROPOSED_ARCHITECTURE.txt`. Bump `pyproject.toml` to `0.3.0`.

**M8 (optional) — Domain service split.** Promote `tapirxl-parse` and `tapirxl-agent`
to standalone processes / containers; the seam is already the envelope JSONL
boundary, so no code changes inside the package.

---

## §16 — Domain Separation & Future Split

Two domains, one package today, two services tomorrow.

| Domain            | Subpackage | Today                                                               | Future                                                 |
| ----------------- | ---------- | ------------------------------------------------------------------- | ------------------------------------------------------ |
| Parsing           | `parser/`  | in-process `pipeline.run(pcap) -> Iterable[HostEnvelope]`           | standalone process exposing JSONL stdio and/or REST    |
| Agentic inventory | `agent/`   | in-process `agent.classify(envelopes) -> Iterable[InventoryRecord]` | standalone process consuming envelopes (stdio or REST) |

**The seam is `HostEnvelope` JSONL.** One envelope per line. JSONL streams
(parser yields as hosts complete; agent classifies as envelopes arrive).
Parser has zero coupling to dspy; agent has zero coupling to pyshark. Adapters
implement the seam:

| Direction    | Today                                           | Future split                                         |
| ------------ | ----------------------------------------------- | ---------------------------------------------------- |
| Parser sink  | `parser/adapters/stdout_sink.py`                | `parser/adapters/rest_sink.py` (HTTP POST)           |
| Agent source | direct call OR `agent/adapters/stdin_source.py` | `agent/adapters/rest_source.py` (HTTP / SSE / queue) |

### Hexagonal hints, not hexagonal religion

Adopt: ports as `typing.Protocol`s (no ABCs); adapters under `adapters/`;
domain code never imports adapters (CLI wires them).

**Skip**: layer-strict `application/`/`domain/`/`infrastructure/` directories;
repository/service/DTO scaffolding; DI containers; event buses.

`core/` exists for primitives belonging to neither domain (MAC, OUI, PHI,
enums, IP). `parser/` and `agent/` both import `core/` and `schemas/`; nothing
in `core/` or `schemas/` imports from `parser/` or `agent/`.

---

## §17 — Implementation Invariants

| #   | Invariant                                                                                                                                                                                                                                                                                           |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| N1  | **Schema stability.** §3 envelope is the public contract. Adding fields is non-breaking; renaming/removing breaks compiled DSPy modules.                                                                                                                                                            |
| N2  | **Envelope identity.** Primary key is MAC. IP is observational. MAC change ⇒ new record. Report this — clinical staff think IP-first.                                                                                                                                                               |
| N3  | **Deterministic-first is load-bearing.** 60–70 % of typical traffic bypasses both LM tiers. Regressions in §6.1 routing multiply wall-clock 5–10×.                                                                                                                                                  |
| N4  | **Normalize verbatim output.** `NormalizeSignal` must output verbatim from `candidate_labels`. Enforced post-hoc; non-matching ⇒ field left ambiguous (cap MEDIUM). No retries — raise compile-set quality instead.                                                                                 |
| N5  | **PHI redaction is mandatory pre-envelope.** HL7 PID-3/5/7/8 and DICOM `(0010,*)` ⇒ `<PHI>`. Institution `(0008,0080)` retained (facility, not patient).                                                                                                                                            |
| N6  | **LM call economy.** Target <1 LM call per ambiguous field, no retries.                                                                                                                                                                                                                             |
| N7  | **Continuous-mode compatibility.** §3 envelope is the future persistence record. Merge rule per MAC: set-union for lists, latest-wins for scalars (timestamped). No schema changes required.                                                                                                        |
| N8  | **Pipeline 3 scope gaps are expected.** Imaging subnet unmirrored, DHCP off-segment, etc. Not a failure.                                                                                                                                                                                            |
| N9  | **Contradiction tone.** Most cross-pipeline contradictions are benign. Triage caps confidence but never auto-fails; fusion reasoning trace MUST cite explicitly.                                                                                                                                    |
| N10 | **No active probing.** All extractors are read-only. No sockets to observed targets, no DNS lookups against observed names.                                                                                                                                                                         |
| N11 | **stdout discipline.** When `--json`, redirect `sys.stdout` → `sys.stderr` immediately; hold the real stdout fd for JSONL. dspy / pyshark / model loaders print to stdout unprompted.                                                                                                               |
| N12 | **Domain dependency direction.** `agent/` and `parser/` may import `core/` and `schemas/`; neither may import the other; `core/` and `schemas/` import nothing from the project.                                                                                                                    |
| N13 | **Model selection is config-driven.** Model names live in `models.toml`, not code. Domain code receives a resolved `ModelConfig`; only `agent/config.py` reads files; only `agent/adapters/ollama_lm.py` constructs `dspy.LM`. Hardcoded model strings in `agent/` (outside `config.py`) are a bug. |

---

## End of Document
