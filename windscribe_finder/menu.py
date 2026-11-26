"""Interactive text menu for Windscribe Connection Finder."""

from __future__ import annotations

import sys
from typing import TextIO

from windscribe_finder.models import (
    WindscribeError,
    WindscribeNotFoundError,
    WindscribeNotReadyError,
)
from windscribe_finder.profiles import (
    DEFAULT_ISP,
    DEFAULT_MODE,
    ProfileStore,
    format_saved_profiles,
)
from windscribe_finder.scanner import (
    DEFAULT_PROTOCOLS,
    parse_csv_list,
    parse_protocol_list,
    run_smart_scan,
)
from windscribe_finder.seams import CommandRunner, ConnectivityProbe
from windscribe_finder.windscribe import (
    WindscribeClient,
    format_amneziawg_presets,
    resolve_cli_path,
)


def _prompt(inp: TextIO, out: TextIO, message: str) -> str | None:
    print(message, end="", file=out, flush=True)
    line = inp.readline()
    if line == "":
        return None
    return line.strip()


def _prompt_with_default(inp: TextIO, out: TextIO, label: str, default: str) -> str | None:
    response = _prompt(inp, out, f"{label} [{default}]: ")
    if response is None:
        return None
    return response if response else default


def _parse_float(raw: str | None, default: float) -> float:
    if not raw:
        return default
    try:
        value = float(raw)
        return value if value > 0 else default
    except ValueError:
        return default


def _parse_bool(raw: str | None, default: bool = False) -> bool:
    if not raw:
        return default
    lower = raw.strip().lower()
    if lower in {"y", "yes", "1", "true"}:
        return True
    if lower in {"n", "no", "0", "false"}:
        return False
    return default


def _render_menu(out: TextIO) -> None:
    print("", file=out)
    print("=== Windscribe Connection Finder ===", file=out)
    print("1. Quick Connect (saved profiles / fast scan)", file=out)
    print("2. Smart Scan (protocol discovery + location sweep)", file=out)
    print("3. Protocol & Port Discovery only", file=out)
    print("4. View Saved Profiles", file=out)
    print("5. View AmneziaWG Presets", file=out)
    print("6. Exit", file=out)
    print("", file=out, flush=True)


def run_interactive_menu(
    *,
    runner: CommandRunner,
    probe: ConnectivityProbe,
    profile_store: ProfileStore,
    cli_path_override: str | None = None,
    default_isp: str = DEFAULT_ISP,
    default_mode: str = DEFAULT_MODE,
    default_timeout: float = 15.0,
    probe_locations: int | None = None,
    probe_timeout: float = 5.0,
    probe_samples: int = 3,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the interactive text menu loop."""
    inp = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    def _get_client() -> WindscribeClient | None:
        try:
            resolved = resolve_cli_path(cli_path_override)
            return WindscribeClient(runner, resolved)
        except WindscribeNotFoundError as exc:
            print(f"Error: {exc}", file=err)
            return None

    def _run_menu_scan(
        *,
        quick: bool,
        discover_only: bool,
        ask_protocols: bool,
        ask_timeout: bool,
        ask_keep_connected: bool,
        default_keep_connected: bool = False,
    ) -> bool:
        """Prompt for scan options and run a smart scan. Returns False on EOF."""
        isp = _prompt_with_default(inp, out, "ISP label", default_isp)
        if isp is None:
            return False
        mode = _prompt_with_default(inp, out, "Anti-censorship mode", default_mode)
        if mode is None:
            return False
        regions_raw = _prompt(inp, out, "Region filter (comma-separated, Enter for all): ")
        if regions_raw is None:
            return False

        protocols = DEFAULT_PROTOCOLS
        ports: tuple[str, ...] = ()
        client: WindscribeClient | None = None
        if ask_protocols:
            protocols_raw = _prompt(
                inp,
                out,
                f"Protocols (comma-separated, Enter for {','.join(DEFAULT_PROTOCOLS)}): ",
            )
            if protocols_raw is None:
                return False
            protocols = parse_protocol_list(protocols_raw)

            client = _get_client()
            ports_by_proto: list[tuple[str, list[str]]] = []
            if client is not None:
                try:
                    for proto in protocols:
                        live_ports = client.list_ports(proto)
                        if live_ports:
                            ports_by_proto.append((proto, live_ports))
                except (WindscribeNotReadyError, WindscribeError):
                    ports_by_proto = []

            if len(ports_by_proto) == 1:
                proto_name, proto_ports = ports_by_proto[0]
                print(
                    f"Available ports for {proto_name}: {', '.join(proto_ports)}",
                    file=out,
                    flush=True,
                )
                ports_prompt = "Ports (comma-separated, Enter for all): "
            elif len(ports_by_proto) > 1:
                print("Available ports:", file=out)
                for proto_name, proto_ports in ports_by_proto:
                    print(f"  {proto_name}: {', '.join(proto_ports)}", file=out)
                out.flush()
                ports_prompt = "Ports (comma-separated, Enter for all): "
            else:
                ports_prompt = "Ports (comma-separated, e.g. 443,80,53; Enter for all): "

            ports_raw = _prompt(inp, out, ports_prompt)
            if ports_raw is None:
                return False
            ports = parse_csv_list(ports_raw)

        timeout = default_timeout
        if ask_timeout:
            timeout_raw = _prompt(inp, out, f"Connect timeout in seconds [{default_timeout:.1f}]: ")
            if timeout_raw is None:
                return False
            timeout = _parse_float(timeout_raw, default_timeout)

        keep_connected = default_keep_connected
        if ask_keep_connected:
            keep_raw = _prompt(inp, out, "Keep connected to best server? [y/N]: ")
            if keep_raw is None:
                return False
            keep_connected = _parse_bool(keep_raw, default=default_keep_connected)

        regions = parse_csv_list(regions_raw)
        if client is None:
            client = _get_client()
        if client is None:
            return True

        try:
            run_smart_scan(
                client,
                probe,
                protocols=protocols,
                ports=ports or None,
                regions=regions or None,
                probe_locations=probe_locations,
                connect_timeout=timeout,
                probe_timeout=probe_timeout,
                probe_samples=probe_samples,
                quick=quick,
                keep_connected=keep_connected,
                discover_only=discover_only,
                profile_store=profile_store,
                isp=isp,
                mode=mode,
                output=out,
            )
        except (WindscribeNotReadyError, WindscribeError) as exc:
            print(f"Error: {exc}", file=err)
        return True

    try:
        while True:
            _render_menu(out)
            choice = _prompt(inp, out, "Select an option [1-6]: ")
            if choice is None:
                print("", file=out)
                return 0

            normalized = choice.strip().lower()
            if normalized in {"6", "0", "q", "quit", "exit"}:
                print("Goodbye.", file=out)
                return 0

            if normalized == "4":
                print(format_saved_profiles(profile_store), file=out)
                continue

            if normalized == "5":
                client = _get_client()
                if client is None:
                    continue
                try:
                    client.check_ready()
                    presets = client.list_amneziawg_presets()
                except (WindscribeNotReadyError, WindscribeError) as exc:
                    print(f"Error: {exc}", file=err)
                    continue
                print(format_amneziawg_presets(presets), file=out)
                continue

            if normalized == "1":
                if not _run_menu_scan(
                    quick=True,
                    discover_only=False,
                    ask_protocols=True,
                    ask_timeout=False,
                    ask_keep_connected=False,
                    default_keep_connected=True,
                ):
                    return 0
                continue

            if normalized == "2":
                if not _run_menu_scan(
                    quick=False,
                    discover_only=False,
                    ask_protocols=True,
                    ask_timeout=True,
                    ask_keep_connected=True,
                    default_keep_connected=False,
                ):
                    return 0
                continue

            if normalized == "3":
                if not _run_menu_scan(
                    quick=False,
                    discover_only=True,
                    ask_protocols=True,
                    ask_timeout=True,
                    ask_keep_connected=False,
                    default_keep_connected=False,
                ):
                    return 0
                continue

            print("Invalid choice. Please enter a number from 1 to 6.", file=out)
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.", file=out)
        return 130
