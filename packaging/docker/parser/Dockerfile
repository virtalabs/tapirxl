## TapirXL parser image — `tapirxl-parser:dev`.
##
## One-shot PCAP -> InventoryRecord JSONL container, fed into the
## `tapirxl-shipper` service via a shared `tapirxl-inventory` volume in
## the demo compose stack. See packaging/docker/README.md for the
## entrypoint contract and packaging/docker/compose.tapirxl.yaml for the
## canonical wiring.
##
## Base pin: `python:3.14-slim-bookworm`. Pinning the Debian release
## (not just `python:3.14-slim`) pins the apt-provided `tshark` version
## by proxy — byte-identical golden equality is sensitive to tshark, not
## just pyshark.

FROM python:3.14-slim-bookworm AS base

# tshark is the deterministic dissector backend pyshark drives.
# ca-certificates is needed if pyshark/tshark ever resolves a hostname
# (currently disabled by parser hard rule N4, kept for defence-in-depth).
# DEBIAN_FRONTEND=noninteractive suppresses tshark's wireshark-group prompt.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends tshark ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# uv handles the Python toolchain. Install via pip (Python is already
# present); we don't need a curl/wget detour for the standalone installer.
RUN pip install --no-cache-dir uv

WORKDIR /app

# Cache-friendly: copy the lockfile + pyproject before the source so
# changes to src/ don't invalidate the dep install layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application sources. `static/` holds the OUI/DICOM/HL7/SNMP lookup
# tables loaded at parse time per CLAUDE.md "version-controlled static
# data".
COPY src/ ./src/
COPY static/ ./static/

# Install the project itself (now that sources are present).
RUN uv sync --frozen --no-dev

# Demo PCAPs live in the parent compose's bind mount at /pcap (read-only);
# parser output lands in the shared `tapirxl-inventory` volume at
# /var/lib/tapirxl/inventory.jsonl.
RUN useradd --system --uid 10001 --shell /usr/sbin/nologin tapirxl \
 && mkdir -p /var/lib/tapirxl /pcap \
 && chown -R tapirxl:tapirxl /var/lib/tapirxl

USER tapirxl

# uv writes the venv at /app/.venv; expose it on PATH so the
# `tapirxl` script resolves without `uv run`.
ENV PATH="/app/.venv/bin:${PATH}"

# `tapirxl` is the canonical entrypoint (typer app at tapirxl.cli:app).
# Demo invocation (one-shot):
#   docker compose run --rm tapirxl-parser \
#     sh -c 'tapirxl parse /pcap/foo.pcap --json >> /var/lib/tapirxl/inventory.jsonl'
#
# A `--output FILE` flag is a deferred follow-up (see plan T3.5); for
# now the demo uses shell redirection inside the container.
ENTRYPOINT ["tapirxl"]
