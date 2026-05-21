"""Entry point for ``tapirxl listen`` — live capture with scheduled per-MAC emits."""

from __future__ import annotations

import argparse
import contextlib
import signal
import sys
import threading
from pathlib import Path
from typing import TextIO

from tapirxl.core.oui import load_oui_table
from tapirxl.parser.live import iter_live_records_threaded
from tapirxl.parser.live_emitter import LiveEmitter

_SHUTDOWN = threading.Event()


def _install_signal_handlers() -> None:
    def _handle(_signum: int, _frame: object) -> None:
        _SHUTDOWN.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)


def run_listen(
    interface: str,
    *,
    emit_inventory: bool = False,
    output: Path | None = None,
    initial_emit_secs: float = 2.0,
    quiescence_secs: float = 30.0,
    heartbeat_secs: float = 300.0,
) -> None:
    """Capture on ``interface`` and emit JSONL on stdout or ``--output PATH``."""
    _install_signal_handlers()
    real_stdout = sys.stdout
    oui_table = load_oui_table(Path.cwd() / "static" / "ieee_oui.txt")

    sink_fp: TextIO | None = None
    try:
        if output is not None:
            sink_fp = open(output, "w", encoding="utf-8", newline="\n")

        def _write_line(line: str) -> None:
            target = sink_fp if sink_fp is not None else real_stdout
            print(line, file=target)
            target.flush()

        emitter = LiveEmitter(
            oui_table,
            initial_emit_secs=initial_emit_secs,
            quiescence_secs=quiescence_secs,
            heartbeat_secs=heartbeat_secs,
            emit_inventory=emit_inventory,
            on_emit=_write_line,
        )

        def _process_idle() -> None:
            emitter.process_due_events()

        with contextlib.redirect_stdout(sys.stderr):
            for record in iter_live_records_threaded(
                interface,
                oui_table,
                shutdown_event=_SHUTDOWN,
                on_idle=_process_idle,
            ):
                emitter.ingest_record(record)
                emitter.process_due_events()
                if _SHUTDOWN.is_set():
                    break

        emitter.process_due_events()
        emitter.drain()
    finally:
        if sink_fp is not None:
            sink_fp.close()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Passive live capture → JSONL on stdout (or --output PATH)."
    )
    p.add_argument(
        "--interface",
        "-i",
        required=True,
        help="Network interface for raw-socket capture (e.g. eth0).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit InventoryRecord JSONL instead of HostEnvelope JSONL.",
    )
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write JSONL to PATH instead of stdout.",
    )
    p.add_argument(
        "--initial-emit-secs",
        type=float,
        default=2.0,
        help="Seconds to buffer a new MAC before the first emission (default: 2).",
    )
    p.add_argument(
        "--quiescence-secs",
        type=float,
        default=30.0,
        help="Seconds of silence before re-emitting an updated MAC (default: 30).",
    )
    p.add_argument(
        "--heartbeat-secs",
        type=float,
        default=300.0,
        help="Maximum seconds between keepalive emissions per MAC (default: 300).",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_arg_parser().parse_args(argv)
    run_listen(
        args.interface,
        emit_inventory=args.json,
        output=args.output,
        initial_emit_secs=args.initial_emit_secs,
        quiescence_secs=args.quiescence_secs,
        heartbeat_secs=args.heartbeat_secs,
    )


if __name__ == "__main__":
    main()
