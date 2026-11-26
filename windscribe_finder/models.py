"""Domain models and exceptions for Windscribe Connection Finder."""

from __future__ import annotations

from dataclasses import dataclass


class WindscribeError(Exception):
    """Base error for Windscribe Connection Finder."""


class WindscribeNotFoundError(WindscribeError):
    """Raised when the Windscribe CLI executable cannot be located."""


class WindscribeNotReadyError(WindscribeError):
    """Raised when Windscribe Desktop is not running or not logged in."""


@dataclass(frozen=True)
class CommandResult:
    """Result of executing an external CLI command."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class ProbeResult:
    """Result of a single external HTTP connectivity probe."""

    reachable: bool
    latency_ms: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class HealthCheckResult:
    """Aggregated result of verifying real external connectivity through a tunnel."""

    healthy: bool
    avg_latency_ms: float | None
    samples_ms: tuple[float, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class AttemptResult:
    """Outcome of a single connect + health-check + disconnect attempt."""

    location: str
    protocol: str
    port: str | None
    connected: bool
    healthy: bool
    avg_latency_ms: float | None = None
    error: str | None = None
    timed_out: bool = False
