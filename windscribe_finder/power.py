"""Prevent display turn-off and system sleep during active scans on Windows."""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Iterator
from contextlib import contextmanager

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002


@contextmanager
def keep_awake(*, enabled: bool = True) -> Iterator[None]:
    """Keep the display and system awake on Windows while inside the context."""
    if not enabled or sys.platform != "win32":
        yield
        return

    set_state = None
    try:
        kernel32 = getattr(ctypes, "windll", None)
        if kernel32 is not None:
            set_state = kernel32.kernel32.SetThreadExecutionState
            set_state(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
    except (AttributeError, OSError):
        set_state = None

    try:
        yield
    finally:
        if set_state is not None:
            try:
                set_state(ES_CONTINUOUS)
            except OSError:
                pass
