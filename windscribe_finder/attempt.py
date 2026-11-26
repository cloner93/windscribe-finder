"""End-to-end single connection attempt orchestration."""

from __future__ import annotations

from collections.abc import Sequence

from windscribe_finder.health import DEFAULT_PROBE_URLS, verify_connectivity
from windscribe_finder.models import AttemptResult
from windscribe_finder.seams import ConnectivityProbe
from windscribe_finder.windscribe import WindscribeClient


def run_single_attempt(
    client: WindscribeClient,
    probe: ConnectivityProbe,
    *,
    location: str,
    protocol: str,
    port: str | None = None,
    connect_timeout: float = 15.0,
    probe_timeout: float = 5.0,
    probe_samples: int = 3,
    probe_urls: Sequence[str] = DEFAULT_PROBE_URLS,
    keep_connected: bool = False,
    check_ready: bool = True,
) -> AttemptResult:
    """Run pre-flight check, connect, verify external connectivity, and cleanly disconnect."""
    if check_ready:
        client.check_ready()

    should_disconnect = True
    try:
        connected, error, timed_out = client.connect(
            location,
            protocol,
            port,
            timeout=connect_timeout,
        )
        if not connected:
            return AttemptResult(
                location=location,
                protocol=protocol,
                port=port,
                connected=False,
                healthy=False,
                avg_latency_ms=None,
                error=error,
                timed_out=timed_out,
            )

        health = verify_connectivity(
            probe,
            urls=probe_urls,
            samples=probe_samples,
            timeout=probe_timeout,
        )
        if health.healthy and keep_connected:
            should_disconnect = False

        return AttemptResult(
            location=location,
            protocol=protocol,
            port=port,
            connected=True,
            healthy=health.healthy,
            avg_latency_ms=health.avg_latency_ms,
            error=health.error,
            timed_out=False,
        )
    finally:
        if should_disconnect:
            client.disconnect()
