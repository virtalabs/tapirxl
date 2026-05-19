## TapirXL unified demo image — `virtalabsinc/tapirxl:demo-<tag>`.
##
## Single image that combines:
##   - parser (python:3.14-slim-bookworm + tshark + uv-managed tapirxl)
##   - Vector binary (copied byte-for-byte from timberio/vector:0.55.0-debian)
##   - mode-switching entrypoint on $TAPIRXL_MODE
##
## Contract (see packaging/docker/README.md "Unified demo image"):
##   TAPIRXL_MODE=pcap (default)
##     -> tapirxl parse $TAPIRXL_PCAP_PATH --json
##        | vector --config-toml /etc/vector/upload-vector.pcap.toml
##     One-shot; container exits when the parser finishes and Vector drains.
##     Uses the stdin-only pcap config so the topology shuts down on EOF
##     instead of waiting on a phantom file source.
##   TAPIRXL_MODE=live
##     -> Stubbed; exits 64 with a message pointing at B1 (live-capture PR).
##
## Version pin: the Vector binary version MUST match
## packaging/docker/vector/Dockerfile (currently 0.55.0-debian). Byte-identical
## golden equality in tests/regression/test_vector_pipeline.py depends on this.
## tests/regression/test_vector_version_pinned.py guards the pin against drift.

# Stage 1: extract the pinned Vector binary from the official image.
FROM timberio/vector:0.55.0-debian AS vector_stage

# Stage 2: parser base + tapirxl + the copied vector binary.
FROM python:3.14-slim-bookworm AS demo

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends tshark ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

# Copy only the Vector binary. Vector is statically linked against glibc;
# bookworm's libc is compatible with the timberio debian image's. The
# `RUN vector --version` smoke step below fails the build fast if any
# shared-library mismatch slips in on a future rebase of the base image.
COPY --from=vector_stage /usr/bin/vector /usr/bin/vector
RUN vector --version

WORKDIR /app

# Cache-friendly: copy the lockfile + pyproject before sources.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application sources + version-controlled static lookup tables.
COPY src/ ./src/
COPY static/ ./static/
RUN uv sync --frozen --no-dev

# Bake the canonical Vector configs + shared VRL.
#   upload-vector.toml       compose long-running (file source)
#   upload-vector.pcap.toml  demo one-shot (stdin -> EOF -> clean shutdown)
# Demo compose can layer in a bind-mount override at either path without
# rebuilding (tests/regression/test_demo_image.py mounts the dryrun config
# over upload-vector.toml to verify byte equality).
COPY configs/upload-vector.toml       /etc/vector/upload-vector.toml
COPY configs/upload-vector.pcap.toml  /etc/vector/upload-vector.pcap.toml
COPY configs/upload-vector.vrl        /etc/vector/upload-vector.vrl
ENV UPLOAD_VECTOR_VRL_PATH=/etc/vector/upload-vector.vrl

# Mode-switching entrypoint script.
COPY packaging/docker/demo/entrypoint.sh /usr/local/bin/tapirxl-demo-entrypoint
RUN chmod +x /usr/local/bin/tapirxl-demo-entrypoint

# Non-root user, uid 10001 matches packaging/docker/parser/Dockerfile so a
# bind-mounted shared volume works without uid surgery.
RUN useradd --system --uid 10001 --shell /usr/sbin/nologin tapirxl \
 && mkdir -p /var/lib/vector/data /pcap \
 && chown -R tapirxl:tapirxl /var/lib/vector

USER tapirxl

ENV PATH="/app/.venv/bin:${PATH}" \
    TAPIRXL_MODE=pcap \
    TAPIRXL_PCAP_PATH=/pcap/synthetic_philips_demo.pcap \
    VECTOR_DATA_DIR=/var/lib/vector/data

# Declarative volume markers; the actual bind mounts come from compose.
VOLUME ["/var/lib/vector/data", "/pcap"]

# tini reaps the parser→vector pipeline's child PIDs cleanly on container
# exit. The entrypoint script `exec`s the pipeline so tini owns both PIDs
# directly.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/tapirxl-demo-entrypoint"]
