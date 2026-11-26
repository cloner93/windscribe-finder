"""Module entry point for `python -m windscribe_finder`."""

from __future__ import annotations

import sys

from windscribe_finder.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
