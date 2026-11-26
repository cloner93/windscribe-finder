# 03: ISP Profile Store, Anti-Censorship Tagging, and Phase 0 Fast-Path

**What to build:** Deliver persistent per-ISP and anti-censorship-mode profile storage backed by a local JSON file with atomic writes, plus Phase 0 fast-path reconnection. Each saved entry tracks `(location, protocol, port)`, success count, failure count, last measured latency, and last verified timestamp under an `(isp, anti_censorship_mode)` key. On subsequent runs, Phase 0 tests previously winning combinations first (ordered by reliability and lowest latency) before falling back to Phase 1/2 discovery. Also expose an option to list available AmneziaWG presets reported by Windscribe CLI so the user can tag their anti-censorship mode accurately.

**Blocked by:** 02: Dynamic Locations/Ports and Two-Phase Smart Scanner

**Status:** resolved

- [x] Persists and loads scan results per `(isp, anti_censorship_mode)` profile in a local JSON file using atomic writes
- [x] Tracks success count, failure count, last latency, and last verified timestamp for each `(location, protocol, port)` entry
- [x] Orders saved entries so reliable, low-latency combinations are prioritized over stale or frequently failing ones
- [x] Runs Phase 0 fast-path before Phase 1/2 when saved entries exist for the active `(isp, anti_censorship_mode)`, returning immediately in quick mode if a saved entry succeeds
- [x] Supports displaying available AmneziaWG presets from Windscribe CLI
- [x] Automated tests verify persistence against real temporary directories on disk, ranking updates after successes/failures, and Phase 0 fast-path behavior
