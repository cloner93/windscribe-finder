"""Command-line entry point for Windscribe Connection Finder."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.menu import run_interactive_menu
from windscribe_finder.models import WindscribeError, WindscribeNotFoundError, WindscribeNotReadyError
from windscribe_finder.profiles import DEFAULT_ISP, DEFAULT_MODE, ProfileStore, format_saved_profiles
from windscribe_finder.scanner import (
    DEFAULT_PROTOCOLS,
    classify_attempt_status,
    format_target,
    parse_csv_list,
    parse_protocol_list,
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
    format_amneziawg_presets,
    resolve_cli_path,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="windscribe_finder",
        description="Test and discover working Windscribe VPN connections.",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Launch the interactive text menu (also default when run with no arguments).",
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
        "--discover-only",
        action="store_true",
        help="Run Phase 1 protocol/port discovery only and skip the Phase 2 location sweep.",
    )
    parser.add_argument(
        "--regions",
        default=None,
        help="Comma-separated region/location filter (case-insensitive, e.g. 'Germany,Netherlands').",
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
        "--ports",
        default=None,
        help="Comma-separated port filter for smart scan (e.g. '443,80,53'; default: all valid ports).",
    )
    parser.add_argument(
        "--probe-locations",
        type=int,
        default=None,
        help="Optional max number of locations to probe during Phase 1 (default: all matched servers).",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Stop scanning as soon as the first verified healthy connection is found and stay connected to it.",
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
    parser.add_argument(
        "--show-profiles",
        action="store_true",
        help="Display saved ISP and anti-censorship profiles and exit.",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: CommandRunner | None = None,
    probe: ConnectivityProbe | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    inp = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    if len(raw_argv) == 0 or args.interactive:
        active_runner = runner if runner is not None else SubprocessCommandRunner()
        active_probe = probe if probe is not None else HttpConnectivityProbe()
        profile_store = ProfileStore(args.profile_path)
        return run_interactive_menu(
            runner=active_runner,
            probe=active_probe,
            profile_store=profile_store,
            cli_path_override=args.cli_path,
            default_isp=args.isp,
            default_mode=args.mode,
            default_timeout=args.timeout,
            probe_locations=args.probe_locations,
            probe_timeout=args.probe_timeout,
            probe_samples=args.probe_samples,
            stdin=inp,
            stdout=out,
            stderr=err,
        )

    if args.show_profiles:
        profile_store = ProfileStore(args.profile_path)
        print(format_saved_profiles(profile_store), file=out)
        return 0

    is_single_attempt = (
        (not args.scan)
        and (not args.discover_only)
        and (args.location is not None or args.protocol is not None)
    )
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
        print(format_amneziawg_presets(presets), file=out)
        return 0

    if not is_single_attempt:
        protocols = parse_protocol_list(args.protocols)
        ports = parse_csv_list(args.ports)
        regions = parse_csv_list(args.regions)
        profile_store = ProfileStore(args.profile_path)
        try:
            scan_result = run_smart_scan(
                client,
                active_probe,
                protocols=protocols,
                ports=ports or None,
                regions=regions or None,
                probe_locations=args.probe_locations,
                connect_timeout=args.timeout,
                probe_timeout=args.probe_timeout,
                probe_samples=args.probe_samples,
                quick=args.quick,
                keep_connected=True if args.keep_connected else None,
                discover_only=args.discover_only,
                profile_store=profile_store,
                isp=args.isp,
                mode=args.mode,
                output=out,
            )
        except (WindscribeNotReadyError, WindscribeError) as exc:
            print(f"Error: {exc}", file=err)
            return 2
        if scan_result.interrupted:
            return 130
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

    target = format_target(result.location, result.protocol, result.port)
    status_label, detail = classify_attempt_status(result)
    if result.healthy and result.avg_latency_ms is not None:
        print(f"{status_label} {target} - avg latency {detail}", file=out)
        return 0

    print(f"{status_label} {target} - {detail}", file=out)
    return 1
