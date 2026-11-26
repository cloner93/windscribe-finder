# Windscribe Connection Finder

A lightweight, zero-dependency Python 3 CLI tool for Windows that automates the official Windscribe Desktop CLI (`windscribe-cli.exe`) to quickly discover working, low-latency VPN protocol, port, and location combinations on restricted networks.

## Prerequisites

- **Windows** with **Python 3.13+** installed (uses Python standard library only — no `pip install` needed).
- **Windscribe Desktop** installed, **running**, and **logged in** before scanning.
- `windscribe-cli.exe` is auto-detected from standard Windows install paths (or pass `--cli-path <path>`).

## Quick Start

### Interactive Menu (One-Click)

Double-click `run.bat`, or run with no arguments:

```powershell
python -m windscribe_finder
```

The interactive menu provides:
1. **Quick Connect** — tries previously working combinations for your ISP/mode first (Phase 0 fast-path) and stays connected to the first verified healthy server.
2. **Smart Scan** — runs Phase 0 (saved profiles), Phase 1 (protocol & port discovery on sample locations), and Phase 2 (location sweep using only working protocol/port pairs), then ranks results by latency.
3. **Protocol & Port Discovery only** — runs Phase 1 to identify which `(protocol, port)` pairs pass through your network without sweeping all locations.
4. **View Saved Profiles** — inspects saved combinations per `(ISP, anti-censorship mode)`.
5. **View AmneziaWG Presets** — lists presets reported by `windscribe-cli amneziawg`.
6. **Exit**

## CLI Usage

### Common Examples

```powershell
# Quick connect using saved profile history for your ISP + anti-censorship mode
python -m windscribe_finder --isp Irancell --mode amneziawg-1 --quick --keep-connected

# Full smart scan filtered to specific regions and protocols
python -m windscribe_finder --scan --isp Shatel --mode off --regions Germany,Netherlands --protocols wireguard,stealth --timeout 12 --keep-connected

# Discover working protocol/port pairs only (skip Phase 2 location sweep)
python -m windscribe_finder --discover-only --protocols wireguard,stealth,wstunnel --probe-locations 2

# Test a single location/protocol/port directly
python -m windscribe_finder --location Germany --protocol stealth --port 8443 --keep-connected

# View saved ISP/mode profiles (works offline)
python -m windscribe_finder --show-profiles

# Display available AmneziaWG presets from Windscribe CLI
python -m windscribe_finder --list-amneziawg
```

### Key Flags

| Flag | Description |
| --- | --- |
| `--interactive`, `-i` | Launch the interactive text menu (default when run with no arguments) |
| `--scan` | Run the full phased smart scanner |
| `--discover-only` | Run Phase 1 protocol/port discovery only (skip Phase 2 sweep) |
| `--isp <name>` | ISP label for saving/loading profiles (default: `default`) |
| `--mode <tag>` | Anti-censorship mode tag, e.g. `off`, `amneziawg-1` (default: `default`) |
| `--regions <csv>` | Case-insensitive comma-separated region/location filter |
| `--protocols <csv>` | Case-insensitive comma-separated protocol filter (`wireguard,stealth,wstunnel,udp,tcp,ikev2`) |
| `--timeout <sec>` | Per-attempt connection timeout in seconds (default: `15.0`) |
| `--quick` | Stop on the first verified healthy connection |
| `--keep-connected` | Stay connected to the verified (or top-ranked) healthy server |
| `--show-profiles` | Print all saved profiles and exit |
| `--list-amneziawg` | Print available AmneziaWG presets from Windscribe CLI and exit |
| `--cli-path <path>` | Override path to `windscribe-cli.exe` |
| `--profile-path <path>` | Override path to the JSON profile store (default: `~/.windscribe_finder/profiles.json`) |

### Notes

- **Anti-Censorship / AmneziaWG**: Configure your desired Anti-Censorship / Protocol Tweaks setting inside Windscribe Desktop, then pass a matching `--mode <tag>` so results are tracked separately per setting.
- **Ctrl+C Handling**: Pressing `Ctrl+C` during a scan cleanly disconnects any in-flight connection, preserves all winning results found so far in the profile store, and prints a partial summary table.

## Running Tests

```powershell
python -m unittest discover -s tests -v
```
