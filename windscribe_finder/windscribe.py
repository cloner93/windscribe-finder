"""Windscribe Desktop CLI discovery and command wrapper."""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Sequence
from pathlib import Path

from windscribe_finder.models import (
    CommandResult,
    WindscribeError,
    WindscribeNotFoundError,
    WindscribeNotReadyError,
)
from windscribe_finder.seams import CommandRunner

_NOT_RUNNING_PHRASES = (
    "not running",
    "is not running",
    "please launch",
    "start windscribe",
    "cannot connect to windscribe",
    "failed to connect to windscribe",
    "windscribe application is not running",
    "app is not running",
)

_NOT_LOGGED_IN_PHRASES = (
    "not logged in",
    "logged out",
    "please log in",
    "login required",
    "sign in",
)

_CONNECT_FAILURE_PHRASES = (
    "failed",
    "error",
    "invalid",
    "unable to connect",
    "could not connect",
    "not found",
)


def _candidate_windows_paths() -> list[Path]:
    candidates: list[Path] = []
    program_files = os.environ.get("PROGRAMFILES")
    if program_files:
        candidates.append(Path(program_files) / "Windscribe" / "windscribe-cli.exe")

    program_files_x86 = os.environ.get("PROGRAMFILES(X86)")
    if program_files_x86:
        candidates.append(Path(program_files_x86) / "Windscribe" / "windscribe-cli.exe")

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs" / "Windscribe" / "windscribe-cli.exe")

    if not program_files and not program_files_x86 and not local_app_data:
        candidates.extend(
            [
                Path(r"C:\Program Files\Windscribe\windscribe-cli.exe"),
                Path(r"C:\Program Files (x86)\Windscribe\windscribe-cli.exe"),
            ]
        )
    return candidates


def resolve_cli_path(cli_path: str | Path | None = None) -> str:
    """Resolve the Windscribe CLI executable path from an override or standard Windows locations."""
    if cli_path is not None:
        explicit = Path(cli_path)
        if not explicit.is_file():
            raise WindscribeNotFoundError(
                f"Windscribe CLI executable not found at '{explicit}'. "
                "Verify the path passed to --cli-path."
            )
        return str(explicit)

    for candidate in _candidate_windows_paths():
        if candidate.is_file():
            return str(candidate)

    for binary_name in ("windscribe-cli", "windscribe-cli.exe"):
        found = shutil.which(binary_name)
        if found:
            return found

    raise WindscribeNotFoundError(
        "Could not locate windscribe-cli.exe automatically. "
        "Install Windscribe Desktop or provide --cli-path <path>."
    )


_DISABLED_RE = re.compile(r"\(\s*disabled\s*\)", re.IGNORECASE)
_STATUS_TAG_RE = re.compile(r"\(\s*(?:pro|10\s*gbps)\s*\)", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^[\s\-_=]+$")
_TABLE_SPLIT_RE = re.compile(r"\t+|\s{2,}")
_PORT_TOKEN_RE = re.compile(r"\b\d{1,5}\b")
_BULLET_PREFIX_RE = re.compile(r"^(?:[-*•]+|\d+[.)])\s+")


def _strip_cli_noise(text: str) -> str:
    """Remove harmless Windscribe CLI logger warnings (e.g. spdlog rotating_file_sink)."""
    cleaned_lines = [
        line
        for line in text.splitlines()
        if not line.lstrip().lower().startswith("spdlog ")
    ]
    return "\n".join(cleaned_lines)


def _extract_connect_location(location: str) -> str:
    """Convert a display location label into a valid `windscribe-cli connect` target.

    `windscribe-cli locations` prints `Region - City - Nickname` (or `Best Location - <Nick>`),
    whereas `windscribe-cli connect` accepts a country code, region, city, nickname, or `best`.
    """
    stripped = location.strip()
    if stripped.lower().startswith("best location"):
        return "best"
    if " - " in stripped:
        parts = [part.strip() for part in stripped.split(" - ") if part.strip()]
        if parts:
            return parts[-1]
    return stripped


def parse_amneziawg_presets(output: str) -> list[str]:
    """Parse available AmneziaWG preset names from `windscribe-cli amneziawg`."""
    presets: list[str] = []
    seen: set[str] = set()
    for raw_line in _strip_cli_noise(output).splitlines():
        stripped = raw_line.strip()
        if not stripped or _SEPARATOR_RE.match(stripped):
            continue
        lower = stripped.lower()
        if stripped.endswith(":") and ("preset" in lower or "amneziawg" in lower):
            continue
        if lower in {"none", "no presets available", "no amneziawg presets available"}:
            continue
        if lower.startswith(("to use a preset", "set protocol tweaks", "amneziawg is used only")):
            continue
        cleaned = _BULLET_PREFIX_RE.sub("", stripped).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            presets.append(cleaned)
    return presets


def format_amneziawg_presets(presets: Sequence[str]) -> str:
    """Format available AmneziaWG presets for human-readable display."""
    if not presets:
        return "No AmneziaWG presets reported by Windscribe CLI."
    lines = ["Available AmneziaWG presets:"]
    lines.extend(f"  - {preset}" for preset in presets)
    return "\n".join(lines)


def parse_ports(output: str) -> list[str]:
    """Parse valid TCP/UDP port numbers (1-65535) from `windscribe-cli ports <protocol>`."""
    ports: list[str] = []
    seen: set[str] = set()
    for match in _PORT_TOKEN_RE.findall(_strip_cli_noise(output)):
        port_num = int(match)
        if 1 <= port_num <= 65535:
            port_str = str(port_num)
            if port_str not in seen:
                seen.add(port_str)
                ports.append(port_str)
    return ports


def _strip_location_tags(text: str) -> str:
    cleaned = _STATUS_TAG_RE.sub("", text)
    return " ".join(cleaned.split()).strip()


def _format_region_city(region: str | None, city: str) -> str:
    if not region or not city:
        return city
    region_lower = region.lower()
    city_lower = city.lower()
    if city_lower == region_lower or city_lower.startswith(f"{region_lower} -"):
        return city
    return f"{region} - {city}"


def parse_locations(output: str) -> list[str]:
    """Parse `windscribe-cli locations` output into clean location names.

    Includes `(Pro)` and `(10 Gbps)` entries while stripping those status tags,
    skipping `(Disabled)` entries, and preserving country/region context
    (`Region - City`) for sectioned and tabular outputs.
    """
    locations: list[str] = []
    seen: set[str] = set()
    section_name: str | None = None
    section_disabled = False
    region_column_index: int | None = None
    city_column_index: int | None = None

    for raw_line in _strip_cli_noise(output).splitlines():
        stripped = raw_line.strip()
        if not stripped or _SEPARATOR_RE.match(stripped):
            continue

        # Detect tabular header lines (e.g. "Location   Short Name   City   Label")
        columns = _TABLE_SPLIT_RE.split(stripped)
        lower_cols = [col.strip().lower() for col in columns]
        if len(columns) >= 2 and lower_cols[0] in {"location", "country", "region"}:
            region_column_index = 0
            if "city" in lower_cols:
                city_column_index = lower_cols.index("city")
            else:
                city_column_index = 0
            section_name = None
            section_disabled = False
            continue

        # Section header ending with ":" (e.g. "Germany:" or "Turkey (Disabled):")
        if stripped.endswith(":") and not raw_line[:1].isspace():
            section_disabled = bool(_DISABLED_RE.search(stripped))
            section_name = _strip_location_tags(_DISABLED_RE.sub("", stripped[:-1]))
            continue

        # Reset section context when returning to top-level non-indented lines
        if not raw_line[:1].isspace():
            section_name = None
            section_disabled = False

        if section_disabled or _DISABLED_RE.search(stripped):
            continue

        if city_column_index is not None and len(columns) > city_column_index:
            city = _strip_location_tags(columns[city_column_index])
            region: str | None = None
            if (
                region_column_index is not None
                and region_column_index != city_column_index
                and len(columns) > region_column_index
            ):
                region = _strip_location_tags(columns[region_column_index])
            candidate = _format_region_city(region, city)
        else:
            city = _strip_location_tags(stripped)
            candidate = _format_region_city(section_name, city)

        if candidate and candidate not in seen:
            seen.add(candidate)
            locations.append(candidate)

    return locations


def _combined_output(result: CommandResult) -> str:
    return _strip_cli_noise(f"{result.stdout}\n{result.stderr}").strip()


def _check_not_ready(result: CommandResult) -> None:
    combined_lower = _combined_output(result).lower()
    if any(phrase in combined_lower for phrase in _NOT_RUNNING_PHRASES):
        raise WindscribeNotReadyError(
            "Windscribe Desktop is not running. "
            "Please open Windscribe Desktop and log in before running this tool."
        )
    if any(phrase in combined_lower for phrase in _NOT_LOGGED_IN_PHRASES):
        raise WindscribeNotReadyError(
            "Windscribe Desktop is not logged in. "
            "Please open Windscribe Desktop and log in before running this tool."
        )


class WindscribeClient:
    """High-level wrapper around the Windscribe Desktop CLI."""

    def __init__(self, runner: CommandRunner, cli_path: str | Path) -> None:
        self._runner = runner
        self._cli_path = str(cli_path)

    @property
    def cli_path(self) -> str:
        return self._cli_path

    def check_ready(self, *, timeout: float = 10.0) -> str:
        """Verify Windscribe Desktop is running and logged in."""
        result = self._runner.run([self._cli_path, "status"], timeout=timeout)
        if result.timed_out:
            raise WindscribeNotReadyError(
                "Timed out checking Windscribe Desktop status. "
                "Please ensure Windscribe Desktop is open and responsive."
            )
        _check_not_ready(result)
        if result.returncode != 0:
            detail = _combined_output(result) or f"exit code {result.returncode}"
            raise WindscribeNotReadyError(
                "Windscribe Desktop is not ready. "
                f"Ensure Windscribe Desktop is open and logged in ({detail})."
            )
        return result.stdout.strip()

    def connect(
        self,
        location: str,
        protocol: str,
        port: str | None = None,
        *,
        timeout: float = 15.0,
    ) -> tuple[bool, str | None, bool]:
        """Attempt to connect to location using protocol and optional port.

        Returns (connected, error_message, timed_out).
        """
        target_location = _extract_connect_location(location)
        proto_spec = protocol.strip()
        if port is not None and str(port).strip():
            proto_spec = f"{proto_spec}:{str(port).strip()}"
        args = [self._cli_path, "connect", target_location, proto_spec]

        result = self._runner.run(args, timeout=timeout)
        if result.timed_out:
            return False, f"Connection timed out after {timeout:.1f}s", True

        _check_not_ready(result)

        combined = _combined_output(result)
        combined_lower = combined.lower()
        if result.returncode != 0:
            return False, combined or f"Windscribe connect failed with exit code {result.returncode}", False

        if "disconnected" in combined_lower and "connected" not in combined_lower.replace("disconnected", ""):
            return False, combined or "Windscribe remained disconnected", False

        if any(phrase in combined_lower for phrase in _CONNECT_FAILURE_PHRASES):
            return False, combined, False

        return True, None, False

    def list_locations(self, *, timeout: float = 10.0) -> list[str]:
        """Fetch and parse available Windscribe locations from the CLI."""
        result = self._runner.run([self._cli_path, "locations"], timeout=timeout)
        if result.timed_out:
            raise WindscribeError("Timed out fetching Windscribe locations.")
        _check_not_ready(result)
        if result.returncode != 0:
            detail = _combined_output(result) or f"exit code {result.returncode}"
            raise WindscribeError(f"Failed to fetch Windscribe locations ({detail}).")
        return parse_locations(result.stdout)

    def list_ports(self, protocol: str, *, timeout: float = 10.0) -> list[str]:
        """Fetch and parse valid ports for the given protocol from the CLI."""
        result = self._runner.run([self._cli_path, "ports", protocol], timeout=timeout)
        if result.timed_out:
            return []
        _check_not_ready(result)
        if result.returncode != 0:
            return []
        return parse_ports(result.stdout)

    def list_amneziawg_presets(self, *, timeout: float = 10.0) -> list[str]:
        """Fetch and parse available AmneziaWG presets from the CLI."""
        result = self._runner.run([self._cli_path, "amneziawg"], timeout=timeout)
        if result.timed_out:
            raise WindscribeError("Timed out fetching AmneziaWG presets.")
        _check_not_ready(result)
        if result.returncode != 0:
            detail = _combined_output(result) or f"exit code {result.returncode}"
            raise WindscribeError(f"Failed to fetch AmneziaWG presets ({detail}).")
        return parse_amneziawg_presets(result.stdout)

    def disconnect(self, *, timeout: float = 10.0) -> CommandResult:
        """Disconnect any active or in-progress Windscribe connection."""
        return self._runner.run([self._cli_path, "disconnect"], timeout=timeout)
