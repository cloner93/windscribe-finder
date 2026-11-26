from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from windscribe_finder.cli import main
from windscribe_finder.models import (
    AttemptResult,
    CommandResult,
    ProbeResult,
    ProfileEntry,
    WindscribeNotReadyError,
)
from windscribe_finder.profiles import ProfileStore
from windscribe_finder.scanner import run_smart_scan
from windscribe_finder.windscribe import WindscribeClient


class TestProfileStorePersistence(unittest.TestCase):
    def test_persists_and_reloads_entries_per_isp_and_mode_with_tracking_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "nested" / "profiles.json"
            store = ProfileStore(store_path)

            t1 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
            t2 = datetime(2026, 11, 21, 12, 30, 0, tzinfo=timezone.utc)

            store.record_attempt(
                "Irancell",
                "amneziawg-1",
                AttemptResult(
                    location="Germany",
                    protocol="wireguard",
                    port="443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=85.5,
                ),
                now=t1,
            )
            store.record_attempt(
                "Irancell",
                "amneziawg-1",
                AttemptResult(
                    location="Germany",
                    protocol="wireguard",
                    port="443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=72.0,
                ),
                now=t2,
            )
            store.record_attempt(
                "Irancell",
                "amneziawg-1",
                AttemptResult(
                    location="Germany",
                    protocol="wireguard",
                    port="443",
                    connected=False,
                    healthy=False,
                    error="timeout",
                    timed_out=True,
                ),
                now=t2,
            )

            # Separate profile under different mode and different ISP must not collide
            store.record_attempt(
                "Irancell",
                "off",
                AttemptResult(
                    location="Netherlands",
                    protocol="stealth",
                    port="8443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=110.0,
                ),
                now=t1,
            )
            store.record_attempt(
                "Shatel",
                "amneziawg-1",
                AttemptResult(
                    location="Switzerland",
                    protocol="wstunnel",
                    port="443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=60.0,
                ),
                now=t1,
            )

            # Verify valid JSON on disk and no leftover temp files from atomic writes
            self.assertTrue(store_path.is_file())
            sibling_files = [p.name for p in store_path.parent.iterdir()]
            self.assertEqual(sibling_files, ["profiles.json"])
            raw_json = json.loads(store_path.read_text(encoding="utf-8"))
            self.assertIsInstance(raw_json, dict)

            # Reload from disk in a brand-new ProfileStore instance
            reloaded = ProfileStore(store_path)
            irancell_awg = reloaded.get_entries("Irancell", "amneziawg-1", now=t2)
            self.assertEqual(len(irancell_awg), 1)
            entry = irancell_awg[0]
            self.assertEqual(
                entry,
                ProfileEntry(
                    location="Germany",
                    protocol="wireguard",
                    port="443",
                    success_count=2,
                    failure_count=1,
                    last_latency_ms=72.0,
                    last_verified_at=t2.isoformat(),
                ),
            )

            irancell_off = reloaded.get_entries("Irancell", "off", now=t2)
            self.assertEqual([(e.location, e.protocol, e.port) for e in irancell_off], [("Netherlands", "stealth", "8443")])

            shatel_awg = reloaded.get_entries("Shatel", "amneziawg-1", now=t2)
            self.assertEqual([(e.location, e.protocol, e.port) for e in shatel_awg], [("Switzerland", "wstunnel", "443")])

            self.assertEqual(
                set(reloaded.list_profiles()),
                {("Irancell", "amneziawg-1"), ("Irancell", "off"), ("Shatel", "amneziawg-1")},
            )

    def test_unseen_failing_attempt_does_not_pollute_saved_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(store_path)

            store.record_attempt(
                "Irancell",
                "default",
                AttemptResult(
                    location="Germany",
                    protocol="wireguard",
                    port="443",
                    connected=False,
                    healthy=False,
                    error="timeout",
                    timed_out=True,
                ),
            )

            self.assertEqual(store.get_entries("Irancell", "default"), [])


class TestProfileRanking(unittest.TestCase):
    def test_orders_reliable_low_latency_entries_above_stale_or_failing_ones(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ProfileStore(Path(tmpdir) / "profiles.json")
            now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
            stale_time = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

            # 1. Frequently failing entry (even though its last latency was low: 40ms)
            store.record_attempt(
                "Irancell",
                "default",
                AttemptResult("France", "wireguard", "443", True, True, 40.0),
                now=now,
            )
            for _ in range(3):
                store.record_attempt(
                    "Irancell",
                    "default",
                    AttemptResult("France", "wireguard", "443", False, False, error="timeout", timed_out=True),
                    now=now,
                )

            # 2. Reliable but stale entry (80ms, verified ~86 days ago)
            store.record_attempt(
                "Irancell",
                "default",
                AttemptResult("Germany", "stealth", "443", True, True, 80.0),
                now=stale_time,
            )

            # 3. Reliable fresh entry with moderate latency (120ms)
            store.record_attempt(
                "Irancell",
                "default",
                AttemptResult("Netherlands", "wstunnel", "443", True, True, 120.0),
                now=now,
            )

            # 4. Reliable fresh entry with lowest latency (65ms)
            store.record_attempt(
                "Irancell",
                "default",
                AttemptResult("Switzerland", "wireguard", "80", True, True, 65.0),
                now=now,
            )

            ordered = store.get_entries("Irancell", "default", now=now)
            self.assertEqual(
                [e.location for e in ordered],
                ["Switzerland", "Netherlands", "Germany", "France"],
            )

    def test_recording_failures_demotes_previously_top_ranked_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ProfileStore(Path(tmpdir) / "profiles.json")
            now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

            store.record_attempt(
                "MCI",
                "off",
                AttemptResult("Germany", "wireguard", "443", True, True, 50.0),
                now=now,
            )
            store.record_attempt(
                "MCI",
                "off",
                AttemptResult("Netherlands", "stealth", "8443", True, True, 90.0),
                now=now,
            )

            # Initially Germany (50ms) ranks ahead of Netherlands (90ms)
            self.assertEqual(
                [e.location for e in store.get_entries("MCI", "off", now=now)],
                ["Germany", "Netherlands"],
            )

            # After Germany starts failing, Netherlands rises to the top
            store.record_attempt(
                "MCI",
                "off",
                AttemptResult("Germany", "wireguard", "443", True, False, error="dead tunnel"),
                now=now,
            )
            self.assertEqual(
                [e.location for e in store.get_entries("MCI", "off", now=now)],
                ["Netherlands", "Germany"],
            )


class TestAmneziaWgPresets(unittest.TestCase):
    def test_client_parses_amneziawg_presets_and_checks_readiness(self) -> None:
        class FakeRunner:
            def __init__(self, responses: list[CommandResult]) -> None:
                self.responses = list(responses)
                self.calls: list[list[str]] = []

            def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
                self.calls.append(list(args))
                return self.responses.pop(0)

        raw_presets = "\n".join(
            [
                "Available AmneziaWG presets:",
                "----------------------------",
                "  - Preset 1",
                "  - Preset 2",
                "  * Custom-IR",
                "  - Preset 1",
            ]
        )
        runner = FakeRunner([CommandResult(returncode=0, stdout=raw_presets, stderr="")])
        client = WindscribeClient(runner, "windscribe-cli.exe")

        presets = client.list_amneziawg_presets()

        self.assertEqual(presets, ["Preset 1", "Preset 2", "Custom-IR"])
        self.assertEqual(runner.calls, [["windscribe-cli.exe", "amneziawg"]])

        not_running_runner = FakeRunner(
            [CommandResult(returncode=1, stdout="", stderr="Windscribe application is not running.")]
        )
        client2 = WindscribeClient(not_running_runner, "windscribe-cli.exe")
        with self.assertRaises(WindscribeNotReadyError):
            client2.list_amneziawg_presets()

    def test_cli_list_amneziawg_displays_available_presets(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.calls: list[list[str]] = []

            def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
                self.calls.append(list(args))
                if args[1] == "status":
                    return CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr="")
                if args[1] == "amneziawg":
                    return CommandResult(
                        returncode=0,
                        stdout="Available AmneziaWG presets:\n  Preset A\n  Preset B\n",
                        stderr="",
                    )
                return CommandResult(returncode=1, stdout="", stderr="unexpected")

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_exe = Path(tmpdir) / "windscribe-cli.exe"
            cli_exe.write_text("", encoding="utf-8")
            runner = FakeRunner()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                ["--cli-path", str(cli_exe), "--list-amneziawg"],
                runner=runner,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            output = out.getvalue()
            self.assertIn("Preset A", output)
            self.assertIn("Preset B", output)
            self.assertEqual(
                runner.calls,
                [
                    [str(cli_exe), "status"],
                    [str(cli_exe), "amneziawg"],
                ],
            )


class FakeVpnEnv:
    """Simulated Windscribe CLI + HTTP probe behind the two outermost seams."""

    def __init__(
        self,
        *,
        locations_output: str,
        ports_by_protocol: dict[str, str],
        outcomes: dict[tuple[str, str, str | None], str | list[float]],
    ) -> None:
        self.locations_output = locations_output
        self.ports_by_protocol = dict(ports_by_protocol)
        self.outcomes = dict(outcomes)
        self.current_connection: tuple[str, str, str | None] | None = None
        self.connect_calls: list[tuple[str, str, str | None]] = []
        self.command_calls: list[list[str]] = []
        self._sample_cursor = 0

    def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
        self.command_calls.append(list(args))
        cmd = args[1]
        if cmd == "status":
            state = f"Connected to {self.current_connection[0]}" if self.current_connection else "Disconnected"
            return CommandResult(returncode=0, stdout=f"Connect state: {state}", stderr="")
        if cmd == "locations":
            return CommandResult(returncode=0, stdout=self.locations_output, stderr="")
        if cmd == "ports":
            return CommandResult(returncode=0, stdout=self.ports_by_protocol.get(args[2], ""), stderr="")
        if cmd == "disconnect":
            self.current_connection = None
            return CommandResult(returncode=0, stdout="Disconnected", stderr="")
        if cmd == "connect":
            location = args[2]
            proto_spec = args[3]
            if ":" in proto_spec:
                protocol, port = proto_spec.split(":", 1)
            else:
                protocol, port = proto_spec, None
            key = (location, protocol, port)
            self.connect_calls.append(key)
            outcome = self.outcomes.get(key, "timeout")
            if outcome == "timeout":
                return CommandResult(returncode=-1, stdout="", stderr="", timed_out=True)
            if outcome == "connect_fail":
                return CommandResult(returncode=1, stdout="", stderr="Failed to connect")
            self.current_connection = key
            self._sample_cursor = 0
            return CommandResult(returncode=0, stdout=f"Connected to {location}", stderr="")
        return CommandResult(returncode=1, stdout="", stderr=f"Unknown command: {cmd}")

    def probe(self, url: str, *, timeout: float) -> ProbeResult:
        if self.current_connection is None:
            return ProbeResult(reachable=False, error="not connected")
        outcome = self.outcomes.get(self.current_connection, "dead_tunnel")
        if isinstance(outcome, list):
            latency = outcome[self._sample_cursor % len(outcome)]
            self._sample_cursor += 1
            return ProbeResult(reachable=True, latency_ms=latency)
        return ProbeResult(reachable=False, error="dead tunnel")


class TestPhase0FastPath(unittest.TestCase):
    def test_phase0_quick_mode_returns_immediately_on_saved_entry_without_phase1_or_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(store_path)
            store.record_attempt(
                "Irancell",
                "amneziawg-1",
                AttemptResult("Germany", "wireguard", "443", True, True, 140.0),
            )
            store.record_attempt(
                "Irancell",
                "amneziawg-1",
                AttemptResult("Switzerland", "stealth", "443", True, True, 55.0),
            )

            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"wireguard": "443\n", "stealth": "443\n"},
                outcomes={
                    ("Switzerland", "stealth", "443"): [50.0, 60.0],
                    ("Germany", "wireguard", "443"): [130.0, 150.0],
                },
            )
            client = WindscribeClient(env, "windscribe-cli.exe")
            out = io.StringIO()

            scan_result = run_smart_scan(
                client,
                env,
                protocols=("wireguard", "stealth"),
                probe_samples=2,
                quick=True,
                keep_connected=True,
                profile_store=store,
                isp="Irancell",
                mode="amneziawg-1",
                output=out,
            )

            # Tested top-ranked saved entry first and stopped immediately
            self.assertEqual(env.connect_calls, [("Switzerland", "stealth", "443")])
            self.assertEqual(env.current_connection, ("Switzerland", "stealth", "443"))
            self.assertIsNotNone(scan_result.connected_result)
            # Skipped Phase 1/2 discovery commands (no locations or ports calls)
            commands = [c[1] for c in env.command_calls]
            self.assertNotIn("locations", commands)
            self.assertNotIn("ports", commands)
            self.assertIn("Phase 0: Saved Profile Fast-Path", out.getvalue())

            # Reload from disk and verify success_count incremented
            reloaded = ProfileStore(store_path)
            entries = reloaded.get_entries("Irancell", "amneziawg-1")
            top = entries[0]
            self.assertEqual(top.location, "Switzerland")
            self.assertEqual(top.success_count, 2)
            self.assertEqual(top.last_latency_ms, 55.0)

    def test_phase0_falls_back_to_phase1_and_2_when_saved_entries_fail_and_records_updates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(store_path)
            store.record_attempt(
                "Irancell",
                "off",
                AttemptResult("Germany", "wireguard", "443", True, True, 60.0),
            )

            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"wireguard": "443\n", "stealth": "8443\n"},
                outcomes={
                    ("Germany", "wireguard", "443"): "timeout",
                    ("Netherlands", "wireguard", "443"): "timeout",
                    ("Germany", "stealth", "8443"): [100.0, 110.0],
                    ("Netherlands", "stealth", "8443"): [70.0, 80.0],
                },
            )
            client = WindscribeClient(env, "windscribe-cli.exe")
            out = io.StringIO()

            scan_result = run_smart_scan(
                client,
                env,
                protocols=("wireguard", "stealth"),
                probe_locations=2,
                probe_samples=2,
                quick=False,
                profile_store=store,
                isp="Irancell",
                mode="off",
                output=out,
            )

            # Phase 0 tested Germany wireguard:443 first, and Phase 1 did not redundantly re-test it
            self.assertEqual(env.connect_calls[0], ("Germany", "wireguard", "443"))
            self.assertEqual(env.connect_calls.count(("Germany", "wireguard", "443")), 1)
            self.assertEqual(
                [(r.location, r.protocol, r.port) for r in scan_result.results],
                [
                    ("Netherlands", "stealth", "8443"),
                    ("Germany", "stealth", "8443"),
                ],
            )

            # Profile store recorded the failure for Germany wireguard:443 and saved the new winners
            reloaded = ProfileStore(store_path)
            entries = reloaded.get_entries("Irancell", "off")
            by_key = {(e.location, e.protocol, e.port): e for e in entries}
            self.assertEqual(by_key[("Germany", "wireguard", "443")].failure_count, 1)
            self.assertEqual(by_key[("Netherlands", "stealth", "8443")].success_count, 1)
            self.assertEqual(by_key[("Germany", "stealth", "8443")].success_count, 1)
            # Reliable new winners now rank ahead of the failing Germany wireguard:443 entry
            self.assertEqual(entries[0].location, "Netherlands")
            self.assertEqual(entries[-1], by_key[("Germany", "wireguard", "443")])

    def test_phase0_full_scan_continues_to_phase1_and_2_without_retesting_phase0_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ProfileStore(Path(tmpdir) / "profiles.json")
            store.record_attempt(
                "Shatel",
                "default",
                AttemptResult("Netherlands", "wireguard", "80", True, True, 95.0),
            )

            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"wireguard": "80\n"},
                outcomes={
                    ("Netherlands", "wireguard", "80"): [90.0, 100.0],
                    ("Germany", "wireguard", "80"): [120.0, 130.0],
                    ("Switzerland", "wireguard", "80"): [50.0, 60.0],
                },
            )
            client = WindscribeClient(env, "windscribe-cli.exe")
            out = io.StringIO()

            scan_result = run_smart_scan(
                client,
                env,
                protocols=("wireguard",),
                probe_locations=1,
                probe_samples=2,
                quick=False,
                profile_store=store,
                isp="Shatel",
                mode="default",
                output=out,
            )

            self.assertEqual(env.connect_calls[0], ("Netherlands", "wireguard", "80"))
            self.assertEqual(len(env.connect_calls), len(set(env.connect_calls)))
            self.assertEqual(
                [r.location for r in scan_result.results],
                ["Switzerland", "Netherlands", "Germany"],
            )

    def test_cli_end_to_end_saves_profile_on_first_run_and_hits_phase0_fast_path_on_second_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_exe = Path(tmpdir) / "windscribe-cli.exe"
            cli_exe.write_text("", encoding="utf-8")
            profile_path = Path(tmpdir) / "profiles.json"

            env1 = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"wireguard": "443\n", "stealth": "8443\n"},
                outcomes={
                    ("Germany", "wireguard", "443"): "timeout",
                    ("Netherlands", "wireguard", "443"): "timeout",
                    ("Germany", "stealth", "8443"): [130.0, 150.0],
                    ("Netherlands", "stealth", "8443"): [50.0, 60.0],
                    ("Switzerland", "stealth", "8443"): [95.0, 105.0],
                },
            )
            out1 = io.StringIO()
            err1 = io.StringIO()
            rc1 = main(
                [
                    "--cli-path",
                    str(cli_exe),
                    "--scan",
                    "--isp",
                    "Irancell",
                    "--mode",
                    "amneziawg-1",
                    "--profile-path",
                    str(profile_path),
                    "--protocols",
                    "wireguard,stealth",
                    "--probe-locations",
                    "2",
                    "--probe-samples",
                    "2",
                ],
                runner=env1,
                probe=env1,
                stdout=out1,
                stderr=err1,
            )
            self.assertEqual(rc1, 0, msg=err1.getvalue())
            self.assertTrue(profile_path.is_file())

            # Second run with --quick --keep-connected must hit Phase 0 fast-path on Netherlands immediately
            env2 = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"wireguard": "443\n", "stealth": "8443\n"},
                outcomes={
                    ("Netherlands", "stealth", "8443"): [48.0, 52.0],
                },
            )
            out2 = io.StringIO()
            err2 = io.StringIO()
            rc2 = main(
                [
                    "--cli-path",
                    str(cli_exe),
                    "--scan",
                    "--isp",
                    "Irancell",
                    "--mode",
                    "amneziawg-1",
                    "--profile-path",
                    str(profile_path),
                    "--quick",
                    "--keep-connected",
                    "--probe-samples",
                    "2",
                ],
                runner=env2,
                probe=env2,
                stdout=out2,
                stderr=err2,
            )
            self.assertEqual(rc2, 0, msg=err2.getvalue())
            self.assertEqual(env2.connect_calls, [("Netherlands", "stealth", "8443")])
            self.assertEqual(env2.current_connection, ("Netherlands", "stealth", "8443"))
            self.assertIn("Phase 0: Saved Profile Fast-Path", out2.getvalue())


if __name__ == "__main__":
    unittest.main()
