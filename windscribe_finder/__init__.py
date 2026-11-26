"""Windscribe Connection Finder package."""

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.models import (
    AttemptResult,
    CommandResult,
    HealthCheckResult,
    ProbeResult,
    ProtocolPort,
    ScanResult,
    WindscribeError,
    WindscribeNotFoundError,
    WindscribeNotReadyError,
)
from windscribe_finder.scanner import (
    DEFAULT_PROTOCOLS,
    format_ranked_table,
    rank_results,
    run_smart_scan,
)
from windscribe_finder.seams import (
    CommandRunner,
    ConnectivityProbe,
    HttpConnectivityProbe,
    SubprocessCommandRunner,
)
from windscribe_finder.windscribe import (
    WindscribeClient,
    parse_locations,
    parse_ports,
    resolve_cli_path,
)

__all__ = [
    "AttemptResult",
    "CommandResult",
    "CommandRunner",
    "ConnectivityProbe",
    "DEFAULT_PROTOCOLS",
    "HealthCheckResult",
    "HttpConnectivityProbe",
    "ProbeResult",
    "ProtocolPort",
    "ScanResult",
    "SubprocessCommandRunner",
    "WindscribeClient",
    "WindscribeError",
    "WindscribeNotFoundError",
    "WindscribeNotReadyError",
    "format_ranked_table",
    "parse_locations",
    "parse_ports",
    "rank_results",
    "resolve_cli_path",
    "run_single_attempt",
    "run_smart_scan",
]
