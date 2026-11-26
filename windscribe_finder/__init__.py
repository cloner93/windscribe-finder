"""Windscribe Connection Finder package."""

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.models import (
    AttemptResult,
    CommandResult,
    HealthCheckResult,
    ProbeResult,
    WindscribeError,
    WindscribeNotFoundError,
    WindscribeNotReadyError,
)
from windscribe_finder.seams import (
    CommandRunner,
    ConnectivityProbe,
    HttpConnectivityProbe,
    SubprocessCommandRunner,
)
from windscribe_finder.windscribe import WindscribeClient, resolve_cli_path

__all__ = [
    "AttemptResult",
    "CommandResult",
    "CommandRunner",
    "ConnectivityProbe",
    "HealthCheckResult",
    "HttpConnectivityProbe",
    "ProbeResult",
    "SubprocessCommandRunner",
    "WindscribeClient",
    "WindscribeError",
    "WindscribeNotFoundError",
    "WindscribeNotReadyError",
    "resolve_cli_path",
    "run_single_attempt",
]
