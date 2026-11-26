"""Two-phase smart scanning engine for Windscribe Connection Finder."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import TextIO

from windscribe_finder.attempt import run_single_attempt
from windscribe_finder.health import DEFAULT_PROBE_URLS
from windscribe_finder.models import AttemptResult, ProtocolPort, ScanResult
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


def _format_target(location: str, protocol: str, port: str | None) -> str:
    return f"{location} [{protocol}:{port}]" if port else f"{location} [{protocol}]"


def _format_attempt_status(result: AttemptResult) -> str:
    if result.healthy and result.avg_latency_ms is not None:
        return f"OK ({result.avg_latency_ms:.1f} ms)"
    if result.timed_out:
        return f"TIMEOUT ({result.error or 'timed out'})"
    if result.connected:
        return f"DEAD TUNNEL ({result.error or 'unreachable'})"
    return f"FAILED ({result.error or 'connect failed'})"


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


def _discover_candidate_pairs(
    client: WindscribeClient,
    protocols: Sequence[str],
) -> list[ProtocolPort]:
    pairs: list[ProtocolPort] = []
    for raw_proto in protocols:
        proto = raw_proto.strip().lower()
        if not proto:
            continue
        ports = client.list_ports(proto)
        if ports:
            for port in ports:
                pairs.append(ProtocolPort(protocol=proto, port=port))
        else:
            pairs.append(ProtocolPort(protocol=proto, port=None))
    return pairs


def run_smart_scan(
    client: WindscribeClient,
    probe: ConnectivityProbe,
    *,
    protocols: Sequence[str] = DEFAULT_PROTOCOLS,
    probe_locations: int = 2,
    connect_timeout: float = 15.0,
    probe_timeout: float = 5.0,
    probe_samples: int = 3,
    probe_urls: Sequence[str] = DEFAULT_PROBE_URLS,
    quick: bool = False,
    keep_connected: bool = False,
    output: TextIO | None = None,
) -> ScanResult:
    """Run two-phase smart scan: Phase 1 protocol/port discovery, Phase 2 location sweep."""
    out = output if output is not None else sys.stdout
    client.check_ready()

    locations = client.list_locations()
    if not locations:
        _emit(out, "No available Windscribe locations found.")
        return ScanResult(working_pairs=(), results=(), all_attempts=(), connected_result=None)

    candidate_pairs = _discover_candidate_pairs(client, protocols)
    if not candidate_pairs:
        _emit(out, "No candidate protocol/port pairs available.")
        return ScanResult(working_pairs=(), results=(), all_attempts=(), connected_result=None)

    sample_count = max(1, min(probe_locations, len(locations)))
    sample_locations = locations[:sample_count]

    working_pairs: list[ProtocolPort] = []
    all_attempts: list[AttemptResult] = []
    tested_keys: set[tuple[str, str, str | None]] = set()
    connected_result: AttemptResult | None = None

    # Phase 1: Protocol & Port Discovery
    _emit(
        out,
        f"Phase 1: Protocol & Port Discovery "
        f"({len(candidate_pairs)} pair(s) x up to {len(sample_locations)} sample location(s))",
    )
    phase1_index = 0
    for pair in candidate_pairs:
        pair_worked = False
        for location in sample_locations:
            phase1_index += 1
            key = (location, pair.protocol, pair.port)
            tested_keys.add(key)

            stay_connected_now = quick and keep_connected
            attempt = run_single_attempt(
                client,
                probe,
                location=location,
                protocol=pair.protocol,
                port=pair.port,
                connect_timeout=connect_timeout,
                probe_timeout=probe_timeout,
                probe_samples=probe_samples,
                probe_urls=probe_urls,
                keep_connected=stay_connected_now,
                check_ready=False,
            )
            all_attempts.append(attempt)
            _emit(
                out,
                f"[Phase 1] [{phase1_index}] "
                f"{_format_target(location, pair.protocol, pair.port)} -> "
                f"{_format_attempt_status(attempt)}",
            )

            if attempt.healthy:
                pair_worked = True
                if pair not in working_pairs:
                    working_pairs.append(pair)
                if stay_connected_now:
                    connected_result = attempt
                break

        if pair_worked and quick:
            ranked = rank_results(all_attempts)
            _emit(out, "")
            _emit(out, format_ranked_table(ranked))
            return ScanResult(
                working_pairs=tuple(working_pairs),
                results=ranked,
                all_attempts=tuple(all_attempts),
                connected_result=connected_result,
            )

    # Phase 2: Location Sweep using only working (protocol, port) pairs
    if working_pairs:
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
        for idx, (location, pair) in enumerate(sweep_jobs, start=1):
            tested_keys.add((location, pair.protocol, pair.port))
            attempt = run_single_attempt(
                client,
                probe,
                location=location,
                protocol=pair.protocol,
                port=pair.port,
                connect_timeout=connect_timeout,
                probe_timeout=probe_timeout,
                probe_samples=probe_samples,
                probe_urls=probe_urls,
                keep_connected=False,
                check_ready=False,
            )
            all_attempts.append(attempt)
            _emit(
                out,
                f"[Phase 2] [{idx}/{len(sweep_jobs)}] "
                f"{_format_target(location, pair.protocol, pair.port)} -> "
                f"{_format_attempt_status(attempt)}",
            )

    ranked = rank_results(all_attempts)
    _emit(out, "")
    _emit(out, format_ranked_table(ranked))

    if keep_connected and ranked and connected_result is None:
        best = ranked[0]
        _emit(
            out,
            f"\nConnecting to best server: {_format_target(best.location, best.protocol, best.port)}...",
        )
        connected, _, _ = client.connect(
            best.location,
            best.protocol,
            best.port,
            timeout=connect_timeout,
        )
        if connected:
            connected_result = best

    return ScanResult(
        working_pairs=tuple(working_pairs),
        results=ranked,
        all_attempts=tuple(all_attempts),
        connected_result=connected_result,
    )
