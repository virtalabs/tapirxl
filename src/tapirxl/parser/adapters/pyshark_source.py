"""pyshark-backed PacketSource."""
from __future__ import annotations

import asyncio
from collections.abc import Iterator

from tapirxl.parser.tables import DISPLAY_FILTER


class PysharkSource:
    def __init__(self, pcap_path: str) -> None:
        self._path = pcap_path

    def packets(self) -> Iterator[object]:
        import pyshark

        loop = asyncio.new_event_loop()
        cap = pyshark.FileCapture(
            self._path,
            display_filter=DISPLAY_FILTER,
            keep_packets=False,
            eventloop=loop,
        )
        try:
            yield from cap
        finally:
            cap.close()
            loop.close()
