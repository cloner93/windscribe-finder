"""Interactive text menu for Windscribe Connection Finder."""

from __future__ import annotations

import sys
from collections.abc import Callable
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
from windscribe_finder.scanner import DEFAULT_PROTOCOLS, run_smart_scan
from windscribe_finder.seams import CommandRunner, ConnectivityProbe
from windscribe_finder.windscribe import WindscribeClient, resolve_cli_path


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


def _parse_csv(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


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
    probe_locations: int = 2,
    probe_timeout: float = 5.0,
    probe_samples: int = 3,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    client_factory: Callable[[], WindscribeClient] | None = None,
) -> int:
    """Run the interactive text menu loop."""
    inp = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    def _get_client() -> WindscribeClient | None:
        try:
            if client_factory is not None:
                return client_factory()
            resolved = resolve_cli_path(cli_path_override)
            return WindscribeClient(runner, resolved)
        except WindscribeNotFoundError as exc:
            print(f"Error: {exc}", file=err)
            return None

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
                if not presets:
                    print("No AmneziaWG presets reported by Windscribe CLI.", file=out)
                else:
                    print("Available AmneziaWG presets:", file=out)
                    for preset in presets:
                        print(f"  - {preset}", file=out)
                continue

            if normalized == "1":
                isp = _prompt_with_default(inp, out, "ISP label", default_isp)
                if isp is None:
                    return 0
                mode = _prompt_with_default(inp, out, "Anti-censorship mode", default_mode)
                if mode is None:
                    return 0
                regions_raw = _prompt(inp, out, "Region filter (comma-separated, Enter for all): ")
                if regions_raw is None:
                    return 0
                regions = _parse_csv(regions_raw)

                client = _get_client()
                if client is None:
                    continue
                try:
                    run_smart_scan(
                        client,
                        probe,
                        regions=regions or None,
                        probe_locations=probe_locations,
                        connect_timeout=default_timeout,
                        probe_timeout=probe_timeout,
                        probe_samples=probe_samples,
                        quick=True,
                        keep_connected=True,
                        profile_store=profile_store,
                        isp=isp,
                        mode=mode,
                        output=out,
                    )
                except (WindscribeNotReadyError, WindscribeError) as exc:
                    print(f"Error: {exc}", file=err)
                continue

            if normalized == "2":
                isp = _prompt_with_default(inp, out, "ISP label", default_isp)
                if isp is None:
                    return 0
                mode = _prompt_with_default(inp, out, "Anti-censorship mode", default_mode)
                if mode is None:
                    return 0
                regions_raw = _prompt(inp, out, "Region filter (comma-separated, Enter for all): ")
                if regions_raw is None:
                    return 0
                protocols_raw = _prompt(
                    inp,
                    out,
                    f"Protocols (comma-separated, Enter for {','.join(DEFAULT_PROTOCOLS)}): ",
                )
                if protocols_raw is None:
                    return 0
                timeout_raw = _prompt(inp, out, f"Connect timeout in seconds [{default_timeout:.1f}]: ")
                if timeout_raw is None:
                    return 0
                keep_raw = _prompt(inp, out, "Keep connected to best server? [y/N]: ")
                if keep_raw is None:
                    return 0

                regions = _parse_csv(regions_raw)
                protocols = tuple(p.lower() for p in _parse_csv(protocols_raw)) or DEFAULT_PROTOCOLS
                timeout = _parse_float(timeout_raw, default_timeout)
                keep_connected = _parse_bool(keep_raw, default=False)

                client = _get_client()
                if client is None:
                    continue
                try:
                    run_smart_scan(
                        client,
                        probe,
                        protocols=protocols,
                        regions=regions or None,
                        probe_locations=probe_locations,
                        connect_timeout=timeout,
                        probe_timeout=probe_timeout,
                        probe_samples=probe_samples,
                        quick=False,
                        keep_connected=keep_connected,
                        profile_store=profile_store,
                        isp=isp,
                        mode=mode,
                        output=out,
                    )
                except (WindscribeNotReadyError, WindscribeError) as exc:
                    print(f"Error: {exc}", file=err)
                continue

            if normalized == "3":
                isp = _prompt_with_default(inp, out, "ISP label", default_isp)
                if isp is None:
                    return 0
                mode = _prompt_with_default(inp, out, "Anti-censorship mode", default_mode)
                if mode is None:
                    return 0
                regions_raw = _prompt(inp, out, "Region filter (comma-separated, Enter for all): ")
                if regions_raw is None:
                    return 0
                protocols_raw = _prompt(
                    inp,
                    out,
                    f"Protocols (comma-separated, Enter for {','.join(DEFAULT_PROTOCOLS)}): ",
                )
                if protocols_raw is None:
                    return 0
                timeout_raw = _prompt(inp, out, f"Connect timeout in seconds [{default_timeout:.1f}]: ")
                if timeout_raw is None:
                    return 0

                regions = _parse_csv(regions_raw)
                protocols = tuple(p.lower() for p in _parse_csv(protocols_raw)) or DEFAULT_PROTOCOLS
                timeout = _parse_float(timeout_raw, default_timeout)

                client = _get_client()
                if client is None:
                    continue
                try:
                    run_smart_scan(
                        client,
                        probe,
                        protocols=protocols,
                        regions=regions or None,
                        probe_locations=probe_locations,
                        connect_timeout=timeout,
                        probe_timeout=probe_timeout,
                        probe_samples=probe_samples,
                        quick=False,
                        keep_connected=False,
                        discover_only=True,
                        profile_store=profile_store,
                        isp=isp,
                        mode=mode,
                        output=out,
                    )
                except (WindscribeNotReadyError, WindscribeError) as exc:
                    print(f"Error: {exc}", file=err)
                continue

            print("Invalid choice. Please enter a number from 1 to 6.", file=out)
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.", file=out)
        return 130
