"""Two-phase smart scanning engine for Windscribe Connection Finder."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import TextIO

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.health import DEFAULT_PROBE_URLS
from windscribe_finder.models import AttemptResult, ProtocolPort, ScanResult
from windscribe_finder.power import keep_awake
from windscribe_finder.profiles import DEFAULT_ISP, DEFAULT_MODE, ProfileStore
from windscribe_finder.seams import ConnectivityProbe
from windscribe_finder.windscribe import WindscribeClient

DEFAULT_PROTOCOLS: tuple[str, ...] = (
    "wireguard",
    "stealth",
    "wstunnel",
    "udp",
    "tcp",
    "ikev2",
)


def format_duration(seconds: float) -> str:
    """Format a duration in seconds as a compact human-readable string (e.g. '45s', '4m 30s', '1h 15m')."""
    total = max(0, int(round(seconds)))
    if total < 60:
        return f"{total}s"
    minutes, rem_seconds = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {rem_seconds}s" if rem_seconds else f"{minutes}m"
    hours, rem_minutes = divmod(minutes, 60)
    return f"{hours}h {rem_minutes}m" if rem_minutes else f"{hours}h"


def format_time_estimate(
    attempt_count: int,
    connect_timeout: float,
    *,
    quick: bool = False,
) -> str:
    """Format a worst-case time estimate line based on attempt count and per-attempt timeout."""
    max_seconds = max(0, attempt_count) * max(0.0, connect_timeout)
    suffix = "; stops early on first healthy connection" if quick else ""
    return (
        f"Estimated max time: up to {format_duration(max_seconds)} "
        f"({attempt_count} attempt(s) x {connect_timeout:.1f}s timeout{suffix})"
    )


def format_target(location: str, protocol: str, port: str | None) -> str:
    """Format a (location, protocol, port) target label."""
    return f"{location} [{protocol}:{port}]" if port else f"{location} [{protocol}]"


def classify_attempt_status(result: AttemptResult) -> tuple[str, str]:
    """Return (status_label, detail) for an AttemptResult."""
    if result.healthy and result.avg_latency_ms is not None:
        return "OK", f"{result.avg_latency_ms:.1f} ms"
    if result.timed_out:
        return "TIMEOUT", result.error or "timed out"
    if result.connected:
        return "DEAD TUNNEL", result.error or "unreachable"
    return "FAILED", result.error or "connect failed"


def format_attempt_status(result: AttemptResult) -> str:
    """Format a compact status string such as 'OK (42.0 ms)' or 'TIMEOUT (...)'."""
    label, detail = classify_attempt_status(result)
    return f"{label} ({detail})"


def parse_csv_list(raw: str | None) -> tuple[str, ...]:
    """Parse a comma-separated string into a tuple of non-empty stripped items."""
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def parse_protocol_list(raw: str | None) -> tuple[str, ...]:
    """Parse a comma-separated protocol list, falling back to DEFAULT_PROTOCOLS."""
    items = tuple(p.lower() for p in parse_csv_list(raw))
    return items or DEFAULT_PROTOCOLS


def _location_region_key(location: str) -> str:
    """Extract the leading country/region token from a location label for diversity grouping."""
    for sep in (" - ", ","):
        if sep in location:
            head = location.split(sep, 1)[0].strip()
            if head:
                return head.lower()
    return location.strip().lower()


def _location_endpoint_key(location: str) -> str:
    """Extract the trailing server/city token to avoid probing duplicate aliases like Best Location - Alphorn."""
    stripped = location.strip()
    if " - " in stripped:
        tail = stripped.rsplit(" - ", 1)[-1].strip()
        if tail:
            return tail.lower()
    return stripped.lower()


def _select_probe_locations(
    locations: Sequence[str],
    sample_count: int | None,
    *,
    cover_all_regions: bool = False,
) -> list[str]:
    """Select probe locations, deduplicating server aliases (e.g. Best Location - Alphorn).

    When ``sample_count`` is ``None`` or ``<= 0``, returns all unique-endpoint locations
    (all servers of the filtered regions, or all servers of all countries if unfiltered).
    When ``sample_count`` is positive, prefers distinct countries/regions up to ``sample_count``
    (or covers all distinct matched regions when ``cover_all_regions`` is True).
    """
    if not locations:
        return []

    if sample_count is None or sample_count <= 0:
        selected_all: list[str] = []
        seen_endpoints: set[str] = set()
        for loc in locations:
            endpoint_key = _location_endpoint_key(loc)
            if endpoint_key in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_key)
            selected_all.append(loc)
        return selected_all

    selected: list[str] = []
    seen_regions: set[str] = set()
    seen_endpoints = set()
    deferred: list[str] = []

    for loc in locations:
        region_key = _location_region_key(loc)
        endpoint_key = _location_endpoint_key(loc)
        if region_key not in seen_regions and endpoint_key not in seen_endpoints:
            seen_regions.add(region_key)
            seen_endpoints.add(endpoint_key)
            selected.append(loc)
            if not cover_all_regions and len(selected) >= max(1, sample_count):
                return selected
        else:
            deferred.append(loc)

    target = max(1, min(sample_count, len(locations)))
    if len(selected) >= target:
        return selected

    for loc in deferred:
        endpoint_key = _location_endpoint_key(loc)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        selected.append(loc)
        if len(selected) >= target:
            return selected

    for loc in deferred:
        if loc not in selected:
            selected.append(loc)
            if len(selected) >= target:
                break
    return selected


def _emit(out: TextIO | None, line: str) -> None:
    if out is None:
        return
    print(line, file=out, flush=True)


def rank_results(results: Sequence[AttemptResult]) -> tuple[AttemptResult, ...]:
    """Return only healthy AttemptResults ranked by lowest average latency."""
    healthy = [r for r in results if r.healthy and r.avg_latency_ms is not None]
    healthy.sort(
        key=lambda r: (
            r.avg_latency_ms if r.avg_latency_ms is not None else float("inf"),
            r.location,
            r.protocol,
            r.port or "",
        )
    )
    return tuple(healthy)


def format_ranked_table(results: Sequence[AttemptResult]) -> str:
    """Format ranked healthy results as a human-readable summary table."""
    if not results:
        return "No working connections found."

    headers = ("Rank", "Location", "Protocol", "Port", "Avg Latency")
    rows = [
        (
            str(idx),
            item.location,
            item.protocol,
            item.port or "-",
            f"{item.avg_latency_ms:.1f} ms" if item.avg_latency_ms is not None else "-",
        )
        for idx, item in enumerate(results, start=1)
    ]
    widths = [
        max(len(headers[col]), max(len(row[col]) for row in rows))
        for col in range(len(headers))
    ]

    def _fmt_row(values: tuple[str, ...]) -> str:
        return "  ".join(val.ljust(widths[col]) for col, val in enumerate(values))

    header_line = _fmt_row(headers)
    sep_line = "  ".join("-" * w for w in widths)
    body_lines = [_fmt_row(row) for row in rows]
    return "\n".join([header_line, sep_line, *body_lines])


def filter_locations(
    locations: Sequence[str],
    regions: Sequence[str] | None = None,
) -> list[str]:
    """Filter locations by case-insensitive substring match against any region filter."""
    if not regions:
        return list(locations)
    tokens = [token.strip().lower() for token in regions if token.strip()]
    if not tokens:
        return list(locations)
    return [loc for loc in locations if any(token in loc.lower() for token in tokens)]


def _discover_candidate_pairs(
    client: WindscribeClient,
    protocols: Sequence[str],
    ports_filter: Sequence[str] | None = None,
) -> list[ProtocolPort]:
    allowed_ports = {p.strip() for p in (ports_filter or ()) if p.strip()}
    pairs: list[ProtocolPort] = []
    for raw_proto in protocols:
        proto = raw_proto.strip().lower()
        if not proto:
            continue
        ports = client.list_ports(proto)
        if ports:
            filtered_ports = [p for p in ports if not allowed_ports or p in allowed_ports]
            for port in filtered_ports:
                pairs.append(ProtocolPort(protocol=proto, port=port))
        elif not allowed_ports:
            pairs.append(ProtocolPort(protocol=proto, port=None))
        else:
            for port in sorted(allowed_ports):
                pairs.append(ProtocolPort(protocol=proto, port=port))
    return pairs


def run_smart_scan(
    client: WindscribeClient,
    probe: ConnectivityProbe,
    *,
    protocols: Sequence[str] = DEFAULT_PROTOCOLS,
    ports: Sequence[str] | None = None,
    regions: Sequence[str] | None = None,
    probe_locations: int | None = None,
    connect_timeout: float = 15.0,
    probe_timeout: float = 5.0,
    probe_samples: int = 3,
    probe_urls: Sequence[str] = DEFAULT_PROBE_URLS,
    quick: bool = False,
    keep_connected: bool | None = None,
    discover_only: bool = False,
    profile_store: ProfileStore | None = None,
    isp: str = DEFAULT_ISP,
    mode: str = DEFAULT_MODE,
    output: TextIO | None = None,
) -> ScanResult:
    """Run smart scan: optional Phase 0 fast-path, Phase 1 discovery, Phase 2 location sweep.

    When ``keep_connected`` is ``None`` (the default), quick mode stays connected
    on the first verified healthy server while full scans disconnect after testing.
    """
    out = output if output is not None else sys.stdout
    client.check_ready()

    effective_keep_connected = quick if keep_connected is None else keep_connected

    working_pairs: list[ProtocolPort] = []
    all_attempts: list[AttemptResult] = []
    tested_keys: set[tuple[str, str, str | None]] = set()
    connected_result: AttemptResult | None = None

    allowed_protocols = {p.strip().lower() for p in protocols if p.strip()}
    allowed_ports = {p.strip() for p in (ports or ()) if p.strip()}
    region_tokens = [r.strip().lower() for r in (regions or ()) if r.strip()]

    def _execute_and_record(
        *,
        phase_label: str,
        progress_label: str,
        location: str,
        protocol: str,
        port: str | None,
        stay_connected: bool = False,
    ) -> AttemptResult:
        tested_keys.add((location, protocol, port))
        attempt = run_single_attempt(
            client,
            probe,
            location=location,
            protocol=protocol,
            port=port,
            connect_timeout=connect_timeout,
            probe_timeout=probe_timeout,
            probe_samples=probe_samples,
            probe_urls=probe_urls,
            keep_connected=stay_connected,
            check_ready=False,
        )
        all_attempts.append(attempt)
        if profile_store is not None:
            profile_store.record_attempt(isp, mode, attempt)
        _emit(
            out,
            f"[{phase_label}] [{progress_label}] "
            f"{format_target(location, protocol, port)} -> "
            f"{format_attempt_status(attempt)}",
        )
        return attempt

    def _finish_quick() -> ScanResult:
        ranked = rank_results(all_attempts)
        _emit(out, "")
        _emit(out, format_ranked_table(ranked))
        return ScanResult(
            working_pairs=tuple(working_pairs),
            results=ranked,
            all_attempts=tuple(all_attempts),
            connected_result=connected_result,
        )

    with keep_awake():
        try:
            # Phase 0: Saved Profile Fast-Path
            if profile_store is not None and not discover_only:
                saved_entries = [
                    entry
                    for entry in profile_store.get_entries(isp, mode)
                    if entry.success_count > 0
                    and (not allowed_protocols or entry.protocol.strip().lower() in allowed_protocols)
                    and (not allowed_ports or (entry.port is not None and entry.port.strip() in allowed_ports))
                    and (not region_tokens or any(tok in entry.location.lower() for tok in region_tokens))
                ]
                if saved_entries:
                    _emit(
                        out,
                        f"Phase 0: Saved Profile Fast-Path "
                        f"({len(saved_entries)} saved entry/entries for '{isp}' / '{mode}')",
                    )
                    _emit(
                        out,
                        format_time_estimate(len(saved_entries), connect_timeout, quick=quick),
                    )
                    for idx, entry in enumerate(saved_entries, start=1):
                        stay_connected_now = quick and effective_keep_connected
                        attempt = _execute_and_record(
                            phase_label="Phase 0",
                            progress_label=f"{idx}/{len(saved_entries)}",
                            location=entry.location,
                            protocol=entry.protocol,
                            port=entry.port,
                            stay_connected=stay_connected_now,
                        )

                        if attempt.healthy:
                            pair = ProtocolPort(protocol=entry.protocol, port=entry.port)
                            if pair not in working_pairs:
                                working_pairs.append(pair)
                            if stay_connected_now:
                                connected_result = attempt
                            if quick:
                                return _finish_quick()

            locations = client.list_locations()
            if region_tokens:
                locations = filter_locations(locations, region_tokens)
            if not locations:
                if region_tokens:
                    filter_desc = ", ".join(r.strip() for r in (regions or ()) if r.strip())
                    _emit(out, f"No locations matched region filter: {filter_desc}.")
                else:
                    _emit(out, "No available Windscribe locations found.")
                ranked = rank_results(all_attempts)
                return ScanResult(
                    working_pairs=tuple(working_pairs),
                    results=ranked,
                    all_attempts=tuple(all_attempts),
                    connected_result=connected_result,
                )

            candidate_pairs = _discover_candidate_pairs(client, protocols, ports)
            if not candidate_pairs:
                _emit(out, "No candidate protocol/port pairs available.")
                ranked = rank_results(all_attempts)
                return ScanResult(
                    working_pairs=tuple(working_pairs),
                    results=ranked,
                    all_attempts=tuple(all_attempts),
                    connected_result=connected_result,
                )

            sample_locations = _select_probe_locations(
                locations,
                probe_locations,
                cover_all_regions=bool(region_tokens),
            )

            # Phase 1: Protocol & Port Discovery
            phase1_total = sum(
                1
                for pair in candidate_pairs
                if pair not in working_pairs
                for location in sample_locations
                if (location, pair.protocol, pair.port) not in tested_keys
            )
            _emit(
                out,
                f"Phase 1: Protocol & Port Discovery "
                f"({len(candidate_pairs)} pair(s) x up to {len(sample_locations)} sample location(s))",
            )
            if phase1_total > 0:
                _emit(
                    out,
                    format_time_estimate(phase1_total, connect_timeout, quick=quick),
                )
            phase1_index = 0
            for pair in candidate_pairs:
                if pair in working_pairs:
                    continue
                pair_worked = False
                for location in sample_locations:
                    key = (location, pair.protocol, pair.port)
                    if key in tested_keys:
                        continue
                    phase1_index += 1

                    stay_connected_now = quick and effective_keep_connected
                    attempt = _execute_and_record(
                        phase_label="Phase 1",
                        progress_label=f"{phase1_index}/{phase1_total}",
                        location=location,
                        protocol=pair.protocol,
                        port=pair.port,
                        stay_connected=stay_connected_now,
                    )

                    if attempt.healthy:
                        pair_worked = True
                        if pair not in working_pairs:
                            working_pairs.append(pair)
                        if stay_connected_now:
                            connected_result = attempt
                        break

                if pair_worked and quick:
                    return _finish_quick()

            # Phase 2: Location Sweep using only working (protocol, port) pairs
            if working_pairs and not discover_only:
                sweep_jobs = [
                    (location, pair)
                    for pair in working_pairs
                    for location in locations
                    if (location, pair.protocol, pair.port) not in tested_keys
                ]
                _emit(
                    out,
                    f"Phase 2: Location Sweep "
                    f"({len(working_pairs)} working pair(s), {len(sweep_jobs)} remaining attempt(s))",
                )
                if sweep_jobs:
                    _emit(
                        out,
                        format_time_estimate(len(sweep_jobs), connect_timeout, quick=False),
                    )
                for idx, (location, pair) in enumerate(sweep_jobs, start=1):
                    _execute_and_record(
                        phase_label="Phase 2",
                        progress_label=f"{idx}/{len(sweep_jobs)}",
                        location=location,
                        protocol=pair.protocol,
                        port=pair.port,
                        stay_connected=False,
                    )

            ranked = rank_results(all_attempts)
            _emit(out, "")
            _emit(out, format_ranked_table(ranked))

            if effective_keep_connected and ranked and connected_result is None:
                for idx, candidate in enumerate(ranked, start=1):
                    target = format_target(candidate.location, candidate.protocol, candidate.port)
                    if idx == 1:
                        _emit(out, f"\nConnecting to best server: {target}...")
                    else:
                        _emit(out, f"Falling back to ranked server #{idx}: {target}...")
                    try:
                        connected, error, timed_out = client.connect(
                            candidate.location,
                            candidate.protocol,
                            candidate.port,
                            timeout=connect_timeout,
                        )
                    except KeyboardInterrupt:
                        client.disconnect()
                        raise
                    if connected:
                        connected_result = candidate
                        break
                    reason = error or ("timed out" if timed_out else "connect failed")
                    _emit(out, f"Warning: failed to reconnect to {target} ({reason}).")
                    client.disconnect()
                if connected_result is None:
                    _emit(out, "Error: failed to reconnect to any ranked server.")

            return ScanResult(
                working_pairs=tuple(working_pairs),
                results=ranked,
                all_attempts=tuple(all_attempts),
                connected_result=connected_result,
            )
        except KeyboardInterrupt:
            ranked = rank_results(all_attempts)
            _emit(out, "\nScan interrupted (Ctrl+C). Partial summary:")
            _emit(out, format_ranked_table(ranked))
            return ScanResult(
                working_pairs=tuple(working_pairs),
                results=ranked,
                all_attempts=tuple(all_attempts),
                connected_result=connected_result,
                interrupted=True,
            )
