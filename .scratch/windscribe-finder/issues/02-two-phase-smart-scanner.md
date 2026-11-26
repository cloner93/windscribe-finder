# 02: Dynamic Locations/Ports and Two-Phase Smart Scanner

**What to build:** Deliver the two-phase smart scanning engine on top of the single-attempt flow. Dynamically fetch available locations (including Pro and 10 Gbps locations, stripping status tags cleanly and excluding Disabled entries) and valid ports per protocol from Windscribe CLI. In Phase 1, probe a small set of sample locations across candidate protocols and their ports to discover which `(protocol, port)` pairs actually pass through the current ISP. In Phase 2, sweep candidate locations using only the working `(protocol, port)` pairs. Print live progress, rank verified working combinations by lowest latency, support quick-stop mode on the first healthy connection, and optionally stay connected to the top-ranked server.

**Blocked by:** 01: CLI Connect and Health Check Tracer Bullet

**Status:** resolved

- [x] Parses `locations` output cleanly, including `(Pro)` and `(10 Gbps)` entries while skipping `(Disabled)` entries
- [x] Dynamically queries valid ports per protocol via `ports <protocol>` instead of relying solely on hardcoded port lists
- [x] Phase 1 probes a small set of sample locations across candidate protocols/ports and filters out blocked `(protocol, port)` pairs
- [x] Phase 2 sweeps candidate locations using only the working `(protocol, port)` pairs from Phase 1 and ranks verified results by lowest average latency
- [x] Supports quick mode (stops on first verified healthy connection) and keep-connected mode (leaves Windscribe connected to the best discovered server)
- [x] Displays live per-attempt progress and a ranked summary table at completion
- [x] Automated tests verify parsing, Phase 1 filtering, Phase 2 sweeping, ranking, quick mode, and keep-connected behavior through the two outermost seams
