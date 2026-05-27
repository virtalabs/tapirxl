"""Top-level CLI entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    name="tapirxl",
    help="Medical Device Traffic — passive device identification",
    no_args_is_help=True,
)


@app.command("parse")
def parse(
    pcap: Annotated[str, typer.Argument(help="Path to input PCAP file")],
    emit_inventory: Annotated[
        bool,
        typer.Option(
            "--json",
            help=(
                "Emit InventoryRecord JSONL (schema: "
                "schemas/inventory_record.schema.json). Default is HostEnvelope JSONL."
            ),
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Write JSONL to PATH (overwrites existing) instead of stdout. "
                "Stdout emits nothing when set; stderr behavior is unchanged."
            ),
        ),
    ] = None,
) -> None:
    """Parse PCAP → JSONL on stdout (or to ``--output PATH``).

    Default emits one HostEnvelope per line (raw deterministic shape).
    With ``--json`` emits one InventoryRecord per line matching
    ``schemas/inventory_record.schema.json``.

    With ``--output PATH`` the same JSONL bytes are written to ``PATH``
    instead of stdout. Useful for one-shot container runs that previously
    relied on shell redirection (``sh -c '... >> /var/lib/tapirxl/...'``).
    """
    from tapirxl.parser.cli import main as _parse_main

    _parse_main(pcap, emit_inventory=emit_inventory, output=output)


@app.command("fixtures")
def fixtures(
    manifest: Annotated[
        str | None,
        typer.Option("--manifest", help="Path to a signal manifest TOML file"),
    ] = None,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Output PCAP path")] = None,
    seed_time: Annotated[
        str | None, typer.Option("--seed-time", help="ISO8601 UTC timestamp")
    ] = None,
) -> None:
    """Regenerate synthetic PCAP fixture."""
    from tapirxl.fixtures.cli import main as _fixtures_main

    argv: list[str] = []
    if manifest:
        argv += ["--manifest", manifest]
    if output:
        argv += ["--output", output]
    if seed_time:
        argv += ["--seed-time", seed_time]
    _fixtures_main(argv)


@app.command("listen")
def listen(
    interface: Annotated[
        str,
        typer.Option("--interface", "-i", help="Network interface for raw-socket capture."),
    ],
    emit_inventory: Annotated[
        bool,
        typer.Option(
            "--json",
            help=(
                "Emit InventoryRecord JSONL (schema: "
                "schemas/inventory_record.schema.json). Default is HostEnvelope JSONL."
            ),
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Write JSONL to PATH (overwrites existing) instead of stdout. "
                "Stdout emits nothing when set; stderr behavior is unchanged."
            ),
        ),
    ] = None,
    initial_emit_secs: Annotated[
        float,
        typer.Option("--initial-emit-secs", help="Seconds before first emit for a new MAC."),
    ] = 2.0,
    quiescence_secs: Annotated[
        float,
        typer.Option("--quiescence-secs", help="Seconds of silence before re-emitting a MAC."),
    ] = 30.0,
    heartbeat_secs: Annotated[
        float,
        typer.Option("--heartbeat-secs", help="Keepalive interval per MAC in seconds."),
    ] = 300.0,
) -> None:
    """Live capture on ``--interface`` → JSONL on stdout (or to ``--output PATH``).

    Long-running until SIGINT/SIGTERM. Emits complete per-MAC envelopes on an
    initial settle window, after quiescence, and on a periodic heartbeat.
    """
    from tapirxl.parser.live_cli import run_listen

    run_listen(
        interface,
        emit_inventory=emit_inventory,
        output=output,
        initial_emit_secs=initial_emit_secs,
        quiescence_secs=quiescence_secs,
        heartbeat_secs=heartbeat_secs,
    )
