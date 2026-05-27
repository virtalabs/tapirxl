"""CLI entry point for ``tapirxl-fixtures`` — generates a synthetic PCAP from a signal manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_DEFAULT_OUTPUT = Path("tests") / "fixtures" / "synthetic_philips_demo.pcap"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Generate a synthetic PCAP from a signal manifest TOML file. "
            "Defaults to the bundled ACMEHOSP demo manifest when --manifest is omitted."
        )
    )
    p.add_argument(
        "--manifest",
        type=str,
        default=None,
        help=("Path to a signal manifest TOML file (default: bundled signal_manifest.toml)"),
    )
    p.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help=(f"Output PCAP path (default: {_DEFAULT_OUTPUT} relative to CWD)"),
    )
    p.add_argument(
        "--seed-time",
        type=str,
        default=None,
        help=(
            "Override scenario.pcap_base_timestamp with an ISO8601 UTC timestamp "
            "(e.g. 2026-05-14T17:00:00Z)"
        ),
    )
    return p


def main(argv: list[str] | None = None) -> Path:
    from tapirxl.fixtures.generator import generate_packets, write_pcap_packets
    from tapirxl.fixtures.loader import load_signal_manifest

    args = build_arg_parser().parse_args(argv)

    manifest_path = Path(args.manifest) if args.manifest else None
    manifest = load_signal_manifest(manifest_path)

    # --seed-time overrides the scenario timestamp at runtime without editing the TOML
    if args.seed_time:
        from datetime import datetime

        seed = datetime.fromisoformat(args.seed_time.replace("Z", "+00:00"))
        manifest = manifest.model_copy(
            update={"scenario": manifest.scenario.model_copy(update={"pcap_base_timestamp": seed})}
        )

    if args.output:
        outp = Path(args.output)
        if not outp.is_absolute():
            outp = (Path.cwd() / outp).resolve()
    else:
        outp = (Path.cwd() / _DEFAULT_OUTPUT).resolve()

    packets = generate_packets(manifest)
    write_pcap_packets(outp, packets)
    print(str(outp), file=sys.stderr)
    return outp


if __name__ == "__main__":
    main()
