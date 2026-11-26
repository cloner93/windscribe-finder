# 04: Interactive Menu, Filters, Graceful Interrupts, and Windows Launcher

**What to build:** Deliver the complete user-facing experience: an interactive text menu when run with no arguments (Quick Connect from saved profiles, Smart Scan, Protocol/Port Discovery only, View Saved Profiles, View AmneziaWG Presets), full CLI flags for non-interactive runs (`--isp`, `--mode`, `--regions`, `--protocols`, `--timeout`, `--quick`, `--keep-connected`), location/region and protocol filtering, graceful `Ctrl+C` handling that cleanly disconnects any in-flight attempt while saving and summarizing partial results, a one-click Windows batch launcher, and a concise README.

**Blocked by:** 03: ISP Profile Store, Anti-Censorship Tagging, and Phase 0 Fast-Path

**Status:** ready-for-agent

- [ ] Running with no arguments launches a clear interactive text menu covering quick connect, smart scan, protocol discovery, saved profiles view, and AmneziaWG presets view
- [ ] Supports full CLI flags for non-interactive execution including ISP, anti-censorship mode, region/location filters, protocol filters, timeout, quick mode, and keep-connected
- [ ] Region/location and protocol filters narrow candidate locations and protocols accurately (case-insensitive matching)
- [ ] Interrupting a running scan with `Ctrl+C` cleanly disconnects any in-flight connection, saves winning results found so far, and prints a partial summary
- [ ] Includes a one-click Windows batch launcher and a concise README explaining prerequisites and usage
- [ ] Automated tests cover CLI flag parsing, interactive menu dispatch, filtering, and graceful interrupt cleanup/persistence
