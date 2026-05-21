"""Live raw-socket capture adapter — read-only pyshark LiveCapture sweep."""

from __future__ import annotations

import asyncio
import queue
import sys
import threading
from collections.abc import Callable, Iterator
from typing import Any

from tapirxl.parser.pipeline import packet_to_records
from tapirxl.parser.tables import DISPLAY_FILTER


def iter_live_records(interface: str, oui_table: dict[str, str]) -> Iterator[dict[str, Any]]:
    """Yield flat signal records from a live interface until capture ends."""
    import pyshark

    pkt_loop = asyncio.new_event_loop()
    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter=DISPLAY_FILTER,
        keep_packets=False,
        eventloop=pkt_loop,
    )
    pkt_count = 0
    try:
        for packet in cap.sniff_continuously():
            pkt_count += 1
            if pkt_count % 5000 == 0:
                print(
                    f"\r  {pkt_count} packets scanned (live)...",
                    end="",
                    file=sys.stderr,
                )
            yield from packet_to_records(packet, oui_table)
    finally:
        cap.close()
        pkt_loop.close()
        print(
            f"\r  {pkt_count} packets scanned (live).",
            file=sys.stderr,
        )


def iter_live_records_threaded(
    interface: str,
    oui_table: dict[str, str],
    *,
    shutdown_event: threading.Event,
    on_idle: Callable[[], None] | None = None,
) -> Iterator[dict[str, Any]]:
    """Threaded live capture with cooperative shutdown for deadline polling."""
    record_queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
    error_holder: list[BaseException] = []

    def _capture() -> None:
        try:
            for record in iter_live_records(interface, oui_table):
                if shutdown_event.is_set():
                    break
                record_queue.put(record)
        except BaseException as exc:
            error_holder.append(exc)
        finally:
            record_queue.put(None)

    thread = threading.Thread(target=_capture, name="tapirxl-live-capture", daemon=True)
    thread.start()
    try:
        while True:
            if error_holder:
                raise error_holder[0]
            try:
                item = record_queue.get(timeout=0.25)
            except queue.Empty:
                if on_idle is not None:
                    on_idle()
                if shutdown_event.is_set() and not thread.is_alive():
                    break
                continue
            if item is None:
                break
            yield item
    finally:
        shutdown_event.set()
        thread.join(timeout=5.0)
        if error_holder:
            raise error_holder[0]
