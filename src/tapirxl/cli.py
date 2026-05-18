"""Top-level CLI entry point."""

from __future__ import annotations

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
) -> None:
    """Parse PCAP → JSONL on stdout.

    Default emits one HostEnvelope per line (raw deterministic shape).
    With ``--json`` emits one InventoryRecord per line matching
    ``schemas/inventory_record.schema.json``.
    """
    from tapirxl.parser.cli import main as _parse_main

    _parse_main(pcap, emit_inventory=emit_inventory)


@app.command("fixtures")
def fixtures(
    output: Annotated[str | None, typer.Option("--output", "-o", help="Output PCAP path")] = None,
    seed_time: Annotated[
        str | None, typer.Option("--seed-time", help="ISO8601 UTC timestamp")
    ] = None,
) -> None:
    """Regenerate synthetic PCAP fixture."""
    from tapirxl.fixtures.cli import main as _fixtures_main

    argv: list[str] = []
    if output:
        argv += ["--output", output]
    if seed_time:
        argv += ["--seed-time", seed_time]
    _fixtures_main(argv)
