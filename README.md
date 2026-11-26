# Windscribe Connection Finder

Zero-dependency Python CLI tool that automates `windscribe-cli` to find working, low-latency protocol/port/server combinations and save them per ISP.

## Requirements

- Python 3.10+ (standard library only, no `pip install` needed)
- **Windscribe Desktop** installed, running, and logged in

## Run

**Windows:** double-click `run.bat` or run:

```powershell
python -m windscribe_finder
```

**Linux:**

```bash
python3 -m windscribe_finder
```

**macOS:**

```bash
python3 -m windscribe_finder --cli-path /Applications/Windscribe.app/Contents/MacOS/windscribe-cli
```

## CLI Examples

```bash
# Quick connect using saved ISP profile (stops & stays connected on first healthy server)
python -m windscribe_finder --scan --isp mci --mode default --quick

# Smart scan filtered by country and protocol
python -m windscribe_finder --scan --isp irancell --regions Germany,Netherlands --protocols wireguard,stealth --keep-connected

# Discover working protocol/port pairs only
python -m windscribe_finder --discover-only

# View saved profiles / AmneziaWG presets
python -m windscribe_finder --show-profiles
python -m windscribe_finder --list-amneziawg
```

Press `Ctrl+C` at any time to cleanly disconnect and keep results found so far.

## Tests

```bash
python -m unittest discover -s tests -v
```
