"""Minimal stub for BlueFlow ``PUT /api/assets/upsert/``.

Used by ``tests/integration/test_phase1_smoke.py`` to validate the full
``tapirxl:demo-dev`` → Vector → BlueFlow upsert path without a live
BlueFlow instance. Stdlib only (``http.server`` / ``threading``).

Upsert semantics mirror the 2026-05-18 integration smoke:
``201 Created`` on first write per ``mac_address``, ``200 OK`` on repeat.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


class _UpsertRecord:
    __slots__ = ("body", "status")

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status = status
        self.body = body


class _Handler(BaseHTTPRequestHandler):
    """Handle ``PUT /api/assets/upsert/`` with DRF-style token auth."""

    def log_message(self, format: str, *args: object) -> None:
        # Quiet by default; pytest surfaces failures from assertions.
        pass

    def do_PUT(self) -> None:
        if self.path.rstrip("/") != "/api/assets/upsert":
            self.send_error(404)
            return

        expected = f"Token {self.server.token}"  # type: ignore[attr-defined]
        auth = self.headers.get("Authorization", "")
        if auth != expected:
            self.send_error(401)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400)
            return

        if not isinstance(body, dict):
            self.send_error(400)
            return

        mac = body.get("mac_address")
        if not isinstance(mac, str):
            self.send_error(400)
            return

        seen: dict[str, bool] = self.server.seen_macs  # type: ignore[attr-defined]
        records: list[_UpsertRecord] = self.server.records  # type: ignore[attr-defined]

        if mac in seen:
            status = 200
        else:
            seen[mac] = True
            status = 201

        records.append(_UpsertRecord(status, body))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")


class BlueFlowStub:
    """Threaded HTTP stub bound to ``127.0.0.1`` on an ephemeral port."""

    def __init__(self, token: str) -> None:
        self._token = token
        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self._server.token = token  # type: ignore[attr-defined]
        self._server.seen_macs = {}  # type: ignore[attr-defined]
        self._server.records = []  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> int:
        """Start the stub and return the bound TCP port."""
        self._thread.start()
        _host, port = self._server.server_address
        return int(port)

    def stop(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)

    def reset(self) -> None:
        """Clear recorded PUTs and MAC upsert state (for idempotent re-run tests)."""
        self._server.seen_macs.clear()  # type: ignore[attr-defined]
        self._server.records.clear()  # type: ignore[attr-defined]

    @property
    def received(self) -> list[_UpsertRecord]:
        return self._server.records  # type: ignore[attr-defined]
