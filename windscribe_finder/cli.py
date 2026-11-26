"""Command-line entry point for Windscribe Connection Finder."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.models import WindscribeError, WindscribeNotFoundError, WindscribeNotReadyError
from windscribe_finder.profiles import DEFAULT_ISP, DEFAULT_MODE, ProfileStore
from windscribe_finder.scanner import DEFAULT_PROTOCOLS, run_smart_scan
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
        description="Test and discover working Windscribe VPN connections.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run the two-phase smart scanner (protocol/port discovery + location sweep).",
    )
    parser.add_argument(
        "--location",
        "-l",
        default=None,
        help="Windscribe location name to connect to for a single attempt (e.g. 'Germany').",
    )
    parser.add_argument(
        "--protocol",
        "-p",
        default=None,
        help="Transport protocol for a single attempt (e.g. wireguard, stealth, wstunnel, udp, tcp, ikev2).",
    )
    parser.add_argument(
        "--port",
        default=None,
        help="Optional port number for a single attempt.",
    )
    parser.add_argument(
        "--protocols",
        default=None,
        help=(
            "Comma-separated candidate protocols for smart scan "
            f"(default: {','.join(DEFAULT_PROTOCOLS)})."
        ),
    )
    parser.add_argument(
        "--probe-locations",
        type=int,
        default=2,
        help="Number of sample locations to probe during Phase 1 discovery (default: 2).",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Stop scanning as soon as the first verified healthy connection is found.",
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
        help="Stay connected to the verified (or top-ranked) healthy server.",
    )
    parser.add_argument(
        "--isp",
        default=DEFAULT_ISP,
        help=f"ISP profile label for saving/loading working combinations (default: {DEFAULT_ISP}).",
    )
    parser.add_argument(
        "--mode",
        default=DEFAULT_MODE,
        help=(
            "Anti-censorship mode tag for saving/loading working combinations "
            f"(e.g. off, amneziawg-1; default: {DEFAULT_MODE})."
        ),
    )
    parser.add_argument(
        "--profile-path",
        default=None,
        help="Optional path to the JSON profile store file.",
    )
    parser.add_argument(
        "--list-amneziawg",
        action="store_true",
        help="Display available AmneziaWG presets reported by Windscribe CLI and exit.",
    )
    return parser


def _parse_protocol_list(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return DEFAULT_PROTOCOLS
    items = tuple(p.strip().lower() for p in raw.split(",") if p.strip())
    return items or DEFAULT_PROTOCOLS


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

    is_single_attempt = (not args.scan) and (args.location is not None or args.protocol is not None)
    if is_single_attempt and (args.location is None or args.protocol is None):
        print("Error: --location and --protocol must both be provided for a single attempt.", file=err)
        return 2

    try:
        cli_path = resolve_cli_path(args.cli_path)
    except WindscribeNotFoundError as exc:
        print(f"Error: {exc}", file=err)
        return 2

    active_runner = runner if runner is not None else SubprocessCommandRunner()
    active_probe = probe if probe is not None else HttpConnectivityProbe()
    client = WindscribeClient(active_runner, cli_path)

    if args.list_amneziawg:
        try:
            client.check_ready()
            presets = client.list_amneziawg_presets()
        except (WindscribeNotReadyError, WindscribeError) as exc:
            print(f"Error: {exc}", file=err)
            return 2
        if not presets:
            print("No AmneziaWG presets reported by Windscribe CLI.", file=out)
        else:
            print("Available AmneziaWG presets:", file=out)
            for preset in presets:
                print(f"  - {preset}", file=out)
        return 0

    if not is_single_attempt:
        protocols = _parse_protocol_list(args.protocols)
        profile_store = ProfileStore(args.profile_path)
        try:
            scan_result = run_smart_scan(
                client,
                active_probe,
                protocols=protocols,
                probe_locations=args.probe_locations,
                connect_timeout=args.timeout,
                probe_timeout=args.probe_timeout,
                probe_samples=args.probe_samples,
                quick=args.quick,
                keep_connected=args.keep_connected,
                profile_store=profile_store,
                isp=args.isp,
                mode=args.mode,
                output=out,
            )
        except (WindscribeNotReadyError, WindscribeError) as exc:
            print(f"Error: {exc}", file=err)
            return 2
        return 0 if scan_result.results else 1

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
