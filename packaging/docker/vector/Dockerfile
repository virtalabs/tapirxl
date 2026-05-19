## TapirXL log-shipper image — `tapirxl-shipper:dev`.
##
## Vector with the TapirXL upload config baked in. Reads
## InventoryRecord JSONL from a shared volume and PUTs translated
## AssetUpsertPayload records to BlueFlow. See
## packaging/docker/README.md for the env-var contract.
##
## Version pin: `0.55.0-debian`. Released 2026-04-22 (latest stable at
## branch time). Byte-identical golden equality depends on this binary's
## JSON serializer; the pin is asserted by
## tests/regression/test_vector_version_pinned.py.

FROM timberio/vector:0.55.0-debian

# Bake the canonical config into the image. Mount overrides (e.g. the
# dryrun config for `just docker-dry-run`) are layered via a bind mount
# in compose.
COPY configs/upload-vector.toml /etc/vector/upload-vector.toml
COPY configs/upload-vector.vrl  /etc/vector/upload-vector.vrl

# Tell the transform where the VRL file lives inside the image.
# Overridable from compose if a custom config layered via bind mount
# wants a different path.
ENV UPLOAD_VECTOR_VRL_PATH=/etc/vector/upload-vector.vrl

# Create a non-root `vector` user with a fixed uid. The upstream image
# runs as root by default; we override for least-privilege. The
# parser-written shared volume `/var/lib/tapirxl/` is created with
# mode 755 + files at 644, which is world-readable, so cross-user reads
# work without uid alignment. We chown the entire `/var/lib/vector/`
# tree so `vector validate` (which writes a temp dir at its parent)
# works without privileges.
RUN useradd --system --uid 10002 --shell /usr/sbin/nologin vector-runtime \
 && mkdir -p /var/lib/tapirxl /var/lib/vector/data \
 && chown -R vector-runtime:vector-runtime /var/lib/vector

# Declarative volume markers: compose binds the shared `tapirxl-inventory`
# named volume at /var/lib/tapirxl for the file source, and a separate
# `tapirxl-spool` volume at /var/lib/vector/data for the disk buffer +
# file source checkpoints.
VOLUME ["/var/lib/tapirxl", "/var/lib/vector/data"]

USER vector-runtime

# Split ENTRYPOINT/CMD so the demo can override CMD to point at the
# dryrun config without rebuilding:
#   docker compose run --rm tapirxl-shipper \
#     --config-toml /etc/vector/upload-vector.dryrun.toml
ENTRYPOINT ["/usr/bin/vector"]
CMD ["--config-toml", "/etc/vector/upload-vector.toml"]
