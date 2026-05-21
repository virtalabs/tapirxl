# TapirXL

> Passive medical-device identification from PCAP files and live network interfaces

TapirXL reads a network capture and produces a structured asset inventory of
medical devices on the wire — with no active probing, no packet injection, and
no external API calls. Three concurrent signal-extraction pipelines (broadcast,
session, DPI) feed a canonical per-MAC `HostEnvelope`. Hosts are classified
deterministically when possible; PHI encountered in HL7 and DICOM traffic is
redacted before any record leaves the parser.

---

## Getting started

### Prerequisites

| Tool                                 | Notes                                                                                         |
| ------------------------------------ | --------------------------------------------------------------------------------------------- |
| Python                               | 3.14+                                                                                         |
| [uv](https://docs.astral.sh/uv/)     | Resolver + venv + lockfile                                                                    |
| [just](https://just.systems/man/en/) | Task runner (optional but handy)                                                              |
| tshark                               | Required by `pyshark` for PCAP dissection — install via Wireshark or `brew install wireshark` |

### Install

```shell
git clone https://github.com/VirtaLabs/TapirXL.git
cd TapirXL
uv sync
```

### Parse a capture

```shell
# InventoryRecord JSONL — one record per MAC on stdout
just parse pcap/your.pcap

# Full HostEnvelope JSONL — raw deterministic shape, all pipeline blocks
just parse-verbose pcap/your.pcap

# Pipe into jq
just parse pcap/your.pcap | jq .

# Live capture on an interface (requires privileges / CAP_NET_ADMIN in containers)
tapirxl listen --interface eth0 --json
```

### Generate the synthetic demo fixture

```shell
just fixture          # writes pcap/synthetic_philips_demo.pcap
just parse pcap/synthetic_philips_demo.pcap | jq .
```

### Ship records to BlueFlow

A Vector pipeline at [`configs/upload-vector.toml`](configs/upload-vector.toml)
translates `InventoryRecord` JSONL to BlueFlow `Asset` upsert payloads
and PUTs them to `${BLUEFLOW_URL}/api/assets/upsert/`. Disk-buffered,
single-flight, at-least-once.

```shell
brew install vectordotdev/brew/vector

# Local dev: pipe the parser through the dry-run config to see translated payloads
just upload-dry-run pcap/synthetic_philips_demo.pcap | jq .

# Containerized: same flow inside the two demo images
just docker-build
just docker-dry-run pcap/synthetic_philips_demo.pcap | jq .
```

See [`packaging/docker/README.md`](packaging/docker/README.md) for the
demo compose-fragment integration and image contract.

---

## How it works

```
PCAP file
   │
   ▼
┌─────────────────────────────────────────────────────────┐
│  Parser (deterministic, LM-free)                        │
│                                                         │
│  Pipeline 1 — Broadcast / multicast                     │
│    WS-Discovery · mDNS · DNS-SD · LLMNR · SSDP · ARP   │
│                                                         │
│  Pipeline 2 — Session / passive OS                      │
│    TCP SYN · TLS Hello · SMB2 · Kerberos · DNS · SSH    │
│                                                         │
│  Pipeline 3 — Event-driven DPI                          │
│    DICOM · DHCP · HL7 MLLP · SNMP                       │
│                 │                                       │
│         PHI redacted here                               │
└─────────────────┬───────────────────────────────────────┘
                  │  per-MAC HostEnvelope
                  ▼
          Triage & deterministic classification
                  │
                  ▼
          InventoryRecord JSONL
```

A host reaches `DETERMINISTIC_FINAL` when consensus confidence is `HIGH` with
no contradictions.

---

## Features

- **Zero active probing** — read-only packet analysis; no packets sent, no DNS
  lookups against observed names.
- **Three signal pipelines** fused into a single canonical envelope keyed on
  MAC address.
- **Deterministic-first** classification; ~60–70 % of hosts are resolved
  without any LM inference.
- **Built-in PHI redaction** — HL7 PID-3/5/7/8 and DICOM `(0010,*)` tags
  replaced with `"<PHI>"` before any record is written.
- **OUI, DHCP fingerprint, DICOM impl-UID, HL7 sending-app, and SNMP sysOID**
  static lookup tables bundled.

---

## Output

One `InventoryRecord` object per line on stdout, conforming to
`schemas/inventory_record.schema.json`:

```jsonc
{
  "host_id": "aa:bb:cc:dd:ee:ff",
  "hostname": "MX800-ICU-3",
  "vendor": "philips",
  "product": "intellivue-mx800",
  "device_class": "PATIENT_MONITOR",
  "confidence": "HIGH",
  "ip": "10.0.1.42",
  "path": "DETERMINISTIC_FINAL",
}
```

---

## Developing

```shell
uv sync --dev          # install all dev dependencies
just fmt               # ruff format
just lint              # ruff check
just test              # pytest
just typecheck         # mypy
```

### Package layout

```
src/tapirxl/
├── core/          # MAC, OUI, PHI redaction, CPE enums, IP sort — no project imports
├── schemas/       # Pydantic v2: SignalObservation, HostEnvelope, InventoryRecord
├── parser/        # Deterministic only — no LM imports
│   ├── extractors/    # one file per protocol
│   ├── pipeline.py
│   ├── envelope_builder.py
│   ├── deterministic.py
│   └── triage.py
├── fixtures/      # Synthetic PCAP generator
└── cli.py         # Typer entry point
```

---

## Contributing

Fork the repository and use a feature branch. Pull requests are welcome for
parser, schema, and core utility work.

Please run `just fmt && just lint && just test` before opening a PR.

---

## Licensing

Proprietary — VirtaLabs. All rights reserved.
