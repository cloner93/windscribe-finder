# 01: CLI Connect and Health Check Tracer Bullet

**What to build:** Set up the zero-dependency Python package and establish both outermost test seams (Windscribe CLI command runner seam and HTTP connectivity probe seam). Deliver an end-to-end single-attempt flow: auto-locate or override the Windscribe CLI executable, run a pre-flight readiness check with a clear message if Windscribe Desktop is not running/logged in, connect to a single specified location/protocol/port with a bounded timeout, verify real external traffic flow and measure average response latency, and cleanly disconnect.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Auto-detects the default Windows Windscribe CLI executable path and supports overriding it via argument/option
- [x] Pre-flight readiness check detects when Windscribe Desktop is not running or not logged in and surfaces a clear actionable error
- [x] Connects to a given location, protocol, and optional port with a bounded timeout and disconnects cleanly on timeout or completion
- [x] Verifies real external HTTPS connectivity after Windscribe reports connected, rejecting "connected but dead" tunnels and returning average latency in milliseconds
- [x] Automated unit tests exercise the end-to-end single-attempt flow through only the two outermost seams (fake command runner and fake connectivity probe) with zero third-party dependencies
