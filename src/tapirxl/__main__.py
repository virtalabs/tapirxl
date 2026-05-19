"""Allow ``python -m tapirxl …`` invocation, mirroring the ``tapirxl`` script entry."""

from __future__ import annotations

from tapirxl.cli import app

if __name__ == "__main__":
    app()
