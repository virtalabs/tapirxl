#!/bin/bash
# TapirXL unified demo image entrypoint.
#
# Switches on $TAPIRXL_MODE:
#   pcap (default): one-shot parser -> Vector pipeline against a mounted PCAP.
#   live          : stubbed; lands in B1 (live-capture PR).
#
# Required env (both modes):
#   BLUEFLOW_URL    Base URL for the BlueFlow HTTP sink.
#   BLUEFLOW_TOKEN  DRF token sent as `Authorization: Token <hex>`.
#
# pcap-mode-only env:
#   TAPIRXL_PCAP_PATH  Path to the PCAP file inside the container.
#
# Vector reads InventoryRecord JSONL from stdin (configs/upload-vector.toml
# has a [sources.inventory_stdin] source with decoding.codec="json"). The
# parser writes the same shape to its stdout, so the pipeline is direct.
#
# Shell choice: bash (not /bin/sh -> dash) because dash 0.5.12 in bookworm
# does not implement `set -o pipefail` and exits the shell on the unknown
# option even with `|| true` masking (set is a POSIX special builtin).
# bash is included in python:3.14-slim-bookworm by default.

set -euo pipefail

: "${TAPIRXL_MODE:=pcap}"
: "${BLUEFLOW_URL:?BLUEFLOW_URL is required}"
: "${BLUEFLOW_TOKEN:?BLUEFLOW_TOKEN is required}"

case "$TAPIRXL_MODE" in
  pcap)
    : "${TAPIRXL_PCAP_PATH:?TAPIRXL_PCAP_PATH is required in pcap mode}"
    tapirxl parse "$TAPIRXL_PCAP_PATH" --json \
      | vector --config-toml /etc/vector/upload-vector.toml
    ;;
  live)
    echo "TAPIRXL_MODE=live is not yet implemented; it will land in B1 (live-capture PR)." >&2
    exit 64
    ;;
  *)
    echo "Unknown TAPIRXL_MODE: $TAPIRXL_MODE  (expected: pcap | live)" >&2
    exit 64
    ;;
esac
