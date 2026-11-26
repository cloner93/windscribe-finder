# Windscribe Connection Finder

Status: ready-for-agent

## Problem Statement

Finding a working, responsive VPN connection in the Windscribe Desktop app on a restricted network is tedious and unpredictable. There are dozens of countries and servers (especially with a Pro account), six transport protocols (WireGuard, IKEv2, OpenVPN UDP, OpenVPN TCP, Stealth, WStunnel), multiple ports per protocol, anti-censorship modes, and multiple ISPs with very different blocking behaviors. Manually clicking through combinations takes a long time, and even when Windscribe reports "Connected", traffic often fails to actually pass through the tunnel or is unacceptably slow.

## Solution

Build a lightweight, zero-dependency Python CLI tool for Windows that automates the official Windscribe Desktop CLI to discover working protocol, port, and location combinations efficiently. Instead of brute-forcing every combination, the tool uses a phased search strategy: first retrying previously successful combinations for the current ISP and anti-censorship tag, then discovering which protocol and port pairs pass through the current network on a small set of probe locations, and finally sweeping candidate locations using only the working protocol/port pairs. Every seemingly connected session is verified with a real connectivity and latency probe before being counted as working, and winning combinations are persisted per ISP and anti-censorship label for fast future reconnects.

## User Stories

1. As a Windscribe Pro user on Windows, I want the tool to automatically locate and invoke the installed Windscribe CLI, so that I do not have to configure binary paths manually on a standard installation.
2. As a user with a custom Windscribe installation path, I want to optionally override the CLI executable path, so that the tool still works outside the default install folder.
3. As a user who forgot to open Windscribe Desktop before running the tool, I want a clear pre-flight error message telling me to open and log in to Windscribe Desktop, so that I immediately know why the scan cannot start.
4. As a user on a restricted network, I want the tool to run with zero third-party Python dependencies, so that I can run it immediately without needing internet access to install packages.
5. As a user who wants to find a working connection fast, I want the tool to first test previously winning combinations saved for my current ISP and anti-censorship mode, so that I can reconnect in seconds without running a full scan.
6. As a user running a full or smart scan on a new ISP, I want the tool to first discover which protocol and port pairs actually work on a small number of probe locations, so that blocked protocols are eliminated quickly instead of wasting time across every country.
7. As a user on an ISP that blocks certain ports, I want the tool to query the available ports for each protocol dynamically from Windscribe rather than hardcoding stale lists, so that only valid ports are tested.
8. As a Windscribe Pro user, I want the tool to include Pro locations when fetching available servers and automatically skip disabled servers, so that I get access to all my paid locations without hitting dead entries.
9. As a user who experiences "connected but no internet" tunnels, I want every successful Windscribe connection to be verified with a real external HTTP connectivity check, so that dead tunnels are rejected.
10. As a user who cares about responsiveness, I want the tool to measure average response latency for each verified connection and rank working combinations from lowest to highest latency, so that I can pick the fastest working option.
11. As a user who does not want to wait forever on a blocked protocol, I want each connection attempt to enforce a short configurable timeout and automatically disconnect and move on when it expires, so that scans stay fast and predictable.
12. As a user switching between multiple ISPs (such as mobile carriers and home broadband), I want working combinations to be saved separately per ISP profile, so that each network builds its own history of reliable settings.
13. As a user experimenting with Windscribe's in-app anti-censorship settings (such as Protocol Tweaks / AmneziaWG presets), I want to tag each scan with an anti-censorship mode label, so that I can record and compare which combinations work under each in-app setting.
14. As a user who wants to see which AmneziaWG presets Windscribe currently has available, I want the tool to optionally display the list reported by Windscribe CLI, so that I can name my anti-censorship labels accurately.
15. As a user who prefers specific countries or regions, I want to be able to filter or prioritize candidate locations, so that the scan focuses on countries I actually want to use.
16. As a user who wants to test only specific protocols, I want to be able to restrict the protocol list for a run, so that I can narrow down a scan when I already have a hunch.
17. As a user running a long scan, I want live progress output showing the current phase, location, protocol, port, and result of each attempt, so that I can see what the tool is doing at all times.
18. As a user who interrupts a scan partway through with Ctrl+C, I want the tool to cleanly disconnect any in-progress attempt and preserve any winning combinations discovered so far, so that no progress is lost and my network is not left in a broken state.
19. As a user who just wants a working connection right now, I want a "quick" mode that stops as soon as the first verified healthy connection is found and stays connected to it, so that I can get online as fast as possible.
20. As a user who wants the best overall connection, I want the tool to present a ranked summary table of all verified working combinations at the end of a scan and optionally connect to the top-ranked one, so that I end up on the best available server.
21. As a user who does not want to memorize CLI flags, I want a simple interactive menu when launching the tool with no arguments (including a one-click Windows batch launcher), so that I can run quick connect, smart scan, protocol discovery, or inspect saved profiles effortlessly.
22. As a power user, I want full command-line flags for ISP, anti-censorship mode, protocols, regions, timeout, quick mode, and keep-connected behavior, so that I can script or repeat exact scans from the terminal.
23. As a user whose saved combinations stop working over time, I want the profile store to track success counts, failure counts, last latency, and last tested timestamps, so that stale combinations drop in priority while reliable ones rise to the top.

## Implementation Decisions

- **Runtime & zero dependencies**: Implement the entire tool using Python 3 standard library only (targeting the installed Python 3.13 environment on Windows), with a simple Windows batch launcher for one-click execution.
- **Windscribe CLI integration**: Wrap the official Windscribe Desktop CLI (version 2.25.8+) as an external subprocess. Use `status` for pre-flight readiness checks, `locations` for server discovery, `ports <protocol>` for valid port discovery, `amneziawg` for displaying available presets, `connect` with non-blocking or bounded-timeout polling for connection attempts, and `disconnect` for clean teardown between attempts.
- **Anti-censorship handling**: Because Windscribe CLI does not expose flags to toggle in-app Anti-Censorship / Protocol Tweaks / AmneziaWG settings directly, the tool will not attempt to mutate Windscribe's internal app preferences. Instead, it treats the active anti-censorship mode as a user-supplied profile tag alongside the ISP name.
- **Phased scanning architecture**:
  - **Phase 0 (Saved Profile Fast-Path)**: Load previously successful `(location, protocol, port)` entries for the `(isp, anti_censorship_mode)` key ordered by reliability and lowest latency, and test them first.
  - **Phase 1 (Protocol & Port Discovery)**: Probe a small set of diverse locations across candidate protocols (`wireguard`, `stealth`, `wstunnel`, `udp`, `tcp`, `ikev2`) and their dynamically fetched ports to identify which `(protocol, port)` pairs actually pass through the current ISP.
  - **Phase 2 (Location Sweep)**: Sweep candidate locations (excluding `(Disabled)` entries, including `(Pro)` entries) using only the working `(protocol, port)` pairs discovered in Phase 1.
- **Real connectivity verification**: After Windscribe reports connected, verify actual traffic flow by issuing lightweight HTTPS requests to standard connectivity check endpoints, measuring average latency across multiple samples, and treating unreachable or timed-out tunnels as failed even if Windscribe reports connected.
- **Profile persistence**: Store ISP + anti-censorship profiles in a local JSON file with atomic writes, recording success count, failure count, last measured latency, and last verified timestamp for each `(location, protocol, port)` tuple.
- **Graceful interruption**: Catch keyboard interrupts during any phase, ensure Windscribe is disconnected cleanly if an attempt was mid-flight, persist all results discovered up to that point, and print a summary before exiting.
- **Dual interface**: Support both an interactive text menu (default when run without subcommands/flags) and direct CLI flags for non-interactive runs.

## Testing Decisions

- **Testing philosophy**: Test external behavior and end-to-end workflows rather than internal implementation details. Avoid mocking internal modules or data structures; exercise parsing, phased scanning, ranking, profile persistence, and CLI orchestration together as real code.
- **Outermost test seams (two seams total)**:
  1. **Command Runner Seam**: A single boundary interface at the outermost subprocess layer that executes Windscribe CLI commands and returns exit code, stdout, and stderr (or timeout). Tests supply a fake command runner to simulate location lists, port lists, successful connections, failed connections, timeouts, and app-not-running errors without needing a live VPN.
  2. **Connectivity Probe Seam**: A single boundary interface at the outermost network layer that executes the real-traffic health check and returns reachability and latency. Tests supply a fake probe to simulate "connected but dead tunnel", high-latency servers, and fast healthy servers deterministically.
- **Real persistence in tests**: Test profile storage against real temporary directories on disk rather than mocking the filesystem.
- **Modules covered**: CLI wrapper parsing and error handling, connectivity health verification logic, phased scanner orchestration (Phase 0 fast-path, Phase 1 discovery, Phase 2 sweep, quick-stop mode, Ctrl+C cleanup), profile storage and ranking, and top-level CLI entry-point flows.
- **Test runner**: Use Python's built-in `unittest` framework so tests also require zero external dependencies.

## Out of Scope

- Automatically modifying Windscribe Desktop's internal GUI preferences, registry keys, or AmneziaWG config files to toggle Anti-Censorship settings without user action.
- Running standalone WireGuard or OpenVPN clients outside of Windscribe Desktop.
- Building a desktop GUI (Tkinter/Qt/Electron) in the initial version; the tool is a clean text/CLI application.
- Full multi-megabyte speed tests (only lightweight reachability and latency checks are in scope).
- macOS or Linux support (targeted specifically at Windows where Windscribe Desktop CLI is installed).

## Further Notes

- Windscribe Desktop must be running and logged in before running scans, as `windscribe-cli` communicates with the desktop app and aborts if the app is not active.
- Users with a Pro account have access to all `(Pro)` and `(10 Gbps)` locations; the location parser should preserve location names cleanly while stripping status tags like `(Pro)` and `(10 Gbps)` and skipping `(Disabled)` entries.
