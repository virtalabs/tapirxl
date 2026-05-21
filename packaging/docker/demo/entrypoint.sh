#!/bin/bash
# TapirXL unified demo image entrypoint.
#
# Switches on $TAPIRXL_MODE:
#   pcap (default): one-shot parser -> Vector pipeline against a mounted PCAP.
#   live          : long-running tapirxl listen -> Vector on shared netns eth0.
#
# Required env (both modes):
#   BLUEFLOW_URL    Base URL for the BlueFlow HTTP sink.
#   BLUEFLOW_TOKEN  DRF token sent as `Authorization: Token <hex>`.
#
# pcap-mode-only env:
#   TAPIRXL_PCAP_PATH  Path to the PCAP file inside the container.
#
# live-mode-only env:
#   TAPIRXL_INTERFACE  Network interface for raw-socket capture (e.g. eth0).
#
# Vector reads InventoryRecord JSONL from stdin (configs/upload-vector.stdin.toml
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

VECTOR_STDIN_CONFIG="/etc/vector/upload-vector.stdin.toml"

case "$TAPIRXL_MODE" in
  pcap)
    : "${TAPIRXL_PCAP_PATH:?TAPIRXL_PCAP_PATH is required in pcap mode}"
    # Stdin-only Vector config: parser -> stdin -> http sink. The topology
    # shuts down when stdin reaches EOF, so the container exits cleanly
    # once the parser finishes and Vector drains its buffer. Do NOT use
    # upload-vector.toml here — its file source has no EOF semantics and
    # the container will hang. See configs/upload-vector.stdin.toml header.
    tapirxl parse "$TAPIRXL_PCAP_PATH" --json \
      | vector --config-toml "$VECTOR_STDIN_CONFIG"
    ;;
  live)
    : "${TAPIRXL_INTERFACE:?TAPIRXL_INTERFACE is required in live mode}"
    listen_args=(--interface "$TAPIRXL_INTERFACE" --json)
    if [ -n "${TAPIRXL_INITIAL_EMIT_SECS:-}" ]; then
      listen_args+=(--initial-emit-secs "$TAPIRXL_INITIAL_EMIT_SECS")
    fi
    if [ -n "${TAPIRXL_QUIESCENCE_SECS:-}" ]; then
      listen_args+=(--quiescence-secs "$TAPIRXL_QUIESCENCE_SECS")
    fi
    if [ -n "${TAPIRXL_HEARTBEAT_SECS:-}" ]; then
      listen_args+=(--heartbeat-secs "$TAPIRXL_HEARTBEAT_SECS")
    fi
    tapirxl listen "${listen_args[@]}" \
      | vector --config-toml "$VECTOR_STDIN_CONFIG"
    ;;
  *)
    echo "Unknown TAPIRXL_MODE: $TAPIRXL_MODE  (expected: pcap | live)" >&2
    exit 64
    ;;
esac
