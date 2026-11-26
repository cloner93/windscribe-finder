"""Outermost test seams for subprocess execution and HTTP connectivity probing."""

from __future__ import annotations

import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Protocol

from windscribe_finder.models import CommandResult, ProbeResult


class CommandRunner(Protocol):
    """Outermost seam for executing Windscribe CLI subprocess commands."""

    def run(self, args: Sequence[str], *, timeout: float | None = None) -> CommandResult:
        """Execute args with an optional timeout and return a CommandResult."""


class ConnectivityProbe(Protocol):
    """Outermost seam for executing a single external HTTP reachability probe."""

    def probe(self, url: str, *, timeout: float) -> ProbeResult:
        """Issue a lightweight HTTP check against url and return reachability and latency."""


class SubprocessCommandRunner:
    """Default CommandRunner backed by Python's subprocess module."""

    def run(self, args: Sequence[str], *, timeout: float | None = None) -> CommandResult:
        try:
            completed = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            return CommandResult(
                returncode=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = (
                exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            return CommandResult(
                returncode=-1,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )


class HttpConnectivityProbe:
    """Default ConnectivityProbe backed by urllib.request."""

    def __init__(self, *, user_agent: str = "windscribe-finder/0.1") -> None:
        self._user_agent = user_agent

    def probe(self, url: str, *, timeout: float) -> ProbeResult:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": self._user_agent},
            method="GET",
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = getattr(response, "status", response.getcode())
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                if 200 <= status < 400:
                    return ProbeResult(reachable=True, latency_ms=elapsed_ms)
                return ProbeResult(
                    reachable=False,
                    error=f"Unexpected HTTP status {status} from {url}",
                )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return ProbeResult(reachable=False, error=str(exc))
