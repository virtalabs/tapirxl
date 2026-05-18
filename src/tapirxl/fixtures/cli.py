"""CLI entry point for `tapirxl-fixtures` — regenerates the synthetic PCAP."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Generate hardcoded synthetic PCAP "
            "(Philips WS-Discovery/DHCP/DICOM + Win7 CT-console vignette)."
        )
    )
    p.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help=(
            "Output PCAP path (default: tests/fixtures/synthetic_philips_demo.pcap relative to CWD)"
        ),
    )
    p.add_argument(
        "--seed-time",
        type=str,
        default=None,
        help="RFC3339/ISO8601 UTC timestamp anchoring PCAP times (e.g. 2026-05-14T17:00:00Z)",
    )
    return p


def main(argv: list[str] | None = None) -> Path:
    from tapirxl.fixtures.builder import (
        assemble_timestamps,
        build_all_scenarios,
        write_pcap_packets,
    )

    args = build_arg_parser().parse_args(argv)

    if args.output:
        outp = Path(args.output)
        if not outp.is_absolute():
            outp = (Path.cwd() / outp).resolve()
    else:
        outp = Path.cwd() / "tests" / "fixtures" / "synthetic_philips_demo.pcap"

    scenarios = build_all_scenarios()
    assemble_timestamps(scenarios, args.seed_time)
    flat_pkts = [pkt for _, pkts in scenarios for pkt in pkts]
    result = write_pcap_packets(outp, flat_pkts)
    print(result, file=sys.stderr)
    return result


if __name__ == "__main__":
    main()
