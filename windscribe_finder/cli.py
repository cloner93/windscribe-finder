"""Command-line entry point for Windscribe Connection Finder."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.models import WindscribeNotFoundError, WindscribeNotReadyError
from windscribe_finder.seams import (
    CommandRunner,
    ConnectivityProbe,
    HttpConnectivityProbe,
    SubprocessCommandRunner,
)
from windscribe_finder.windscribe import WindscribeClient, resolve_cli_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="windscribe_finder",
        description="Test and verify Windscribe VPN connections.",
    )
    parser.add_argument(
        "--location",
        "-l",
        required=True,
        help="Windscribe location name to connect to (e.g. 'Germany' or 'Frankfurt').",
    )
    parser.add_argument(
        "--protocol",
        "-p",
        required=True,
        help="Transport protocol (e.g. wireguard, stealth, wstunnel, udp, tcp, ikev2).",
    )
    parser.add_argument(
        "--port",
        default=None,
        help="Optional port number for the chosen protocol.",
    )
    parser.add_argument(
        "--cli-path",
        default=None,
        help="Optional path to windscribe-cli.exe (auto-detected by default).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Connection timeout in seconds (default: 15.0).",
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=5.0,
        help="Per-request HTTP connectivity probe timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--probe-samples",
        type=int,
        default=3,
        help="Number of HTTP latency samples to average (default: 3).",
    )
    parser.add_argument(
        "--keep-connected",
        action="store_true",
        help="Stay connected if the tunnel passes the health check.",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: CommandRunner | None = None,
    probe: ConnectivityProbe | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        cli_path = resolve_cli_path(args.cli_path)
    except WindscribeNotFoundError as exc:
        print(f"Error: {exc}", file=err)
        return 2

    active_runner = runner if runner is not None else SubprocessCommandRunner()
    active_probe = probe if probe is not None else HttpConnectivityProbe()
    client = WindscribeClient(active_runner, cli_path)

    try:
        result = run_single_attempt(
            client,
            active_probe,
            location=args.location,
            protocol=args.protocol,
            port=args.port,
            connect_timeout=args.timeout,
            probe_timeout=args.probe_timeout,
            probe_samples=args.probe_samples,
            keep_connected=args.keep_connected,
        )
    except WindscribeNotReadyError as exc:
        print(f"Error: {exc}", file=err)
        return 2

    target = f"{result.location} [{result.protocol}" + (
        f":{result.port}]" if result.port else "]"
    )

    if result.healthy and result.avg_latency_ms is not None:
        print(f"OK {target} - avg latency {result.avg_latency_ms:.1f} ms", file=out)
        return 0

    reason = result.error or "Unknown failure"
    status_label = "TIMEOUT" if result.timed_out else "DEAD TUNNEL" if result.connected else "FAILED"
    print(f"{status_label} {target} - {reason}", file=out)
    return 1
