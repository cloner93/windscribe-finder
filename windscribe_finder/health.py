"""Real external HTTPS connectivity verification and latency measurement."""

from __future__ import annotations

from collections.abc import Sequence

from windscribe_finder.models import HealthCheckResult
from windscribe_finder.seams import ConnectivityProbe

DEFAULT_PROBE_URLS: tuple[str, ...] = (
    "https://connectivitycheck.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)


def verify_connectivity(
    probe: ConnectivityProbe,
    *,
    urls: Sequence[str] = DEFAULT_PROBE_URLS,
    samples: int = 3,
    timeout: float = 5.0,
) -> HealthCheckResult:
    """Verify real external traffic flows through the tunnel and measure average latency."""
    if not urls:
        raise ValueError("At least one probe URL is required.")
    if samples < 1:
        raise ValueError("samples must be at least 1.")

    latencies: list[float] = []
    active_url = urls[0]

    for sample_index in range(samples):
        candidate_urls = (
            urls if sample_index == 0 else (active_url, *[u for u in urls if u != active_url])
        )
        sample_latency: float | None = None
        last_error: str | None = None

        for url in candidate_urls:
            result = probe.probe(url, timeout=timeout)
            if result.reachable and result.latency_ms is not None:
                sample_latency = result.latency_ms
                active_url = url
                break
            last_error = result.error or f"Probe failed for {url}"

        if sample_latency is None:
            return HealthCheckResult(
                healthy=False,
                avg_latency_ms=None,
                samples_ms=tuple(latencies),
                error=last_error or "Connectivity probe failed",
            )

        latencies.append(sample_latency)

    avg_ms = sum(latencies) / len(latencies)
    return HealthCheckResult(
        healthy=True,
        avg_latency_ms=avg_ms,
        samples_ms=tuple(latencies),
    )
