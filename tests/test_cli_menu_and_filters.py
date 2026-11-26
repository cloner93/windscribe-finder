from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from windscribe_finder.cli import main
from windscribe_finder.models import AttemptResult, CommandResult, ProbeResult
from windscribe_finder.profiles import ProfileStore
from windscribe_finder.scanner import run_smart_scan
from windscribe_finder.windscribe import WindscribeClient


class FakeVpnEnv:
    """Fake outermost CommandRunner + ConnectivityProbe for end-to-end tests."""

    def __init__(
        self,
        *,
        locations_output: str = "",
        ports_by_protocol: dict[str, str] | None = None,
        amneziawg_output: str = "",
        outcomes: dict[tuple[str, str, str | None], object] | None = None,
        interrupt_on_connect: tuple[str, str, str | None] | None = None,
        interrupt_on_probe: tuple[str, str, str | None] | None = None,
    ) -> None:
        self._locations_output = locations_output
        self._ports_by_protocol = ports_by_protocol or {}
        self._amneziawg_output = amneziawg_output
        self._outcomes = dict(outcomes or {})
        self._interrupt_on_connect = interrupt_on_connect
        self._interrupt_on_probe = interrupt_on_probe
        self.current_connection: tuple[str, str, str | None] | None = None
        self.connect_calls: list[tuple[str, str, str | None]] = []
        self.disconnect_count = 0
        self.commands: list[list[str]] = []

    def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
        self.commands.append(list(args))
        cmd = args[1] if len(args) > 1 else ""
        if cmd == "status":
            return CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr="")
        if cmd == "locations":
            return CommandResult(returncode=0, stdout=self._locations_output, stderr="")
        if cmd == "ports":
            proto = args[2].lower() if len(args) > 2 else ""
            return CommandResult(returncode=0, stdout=self._ports_by_protocol.get(proto, ""), stderr="")
        if cmd == "amneziawg":
            return CommandResult(returncode=0, stdout=self._amneziawg_output, stderr="")
        if cmd == "disconnect":
            self.disconnect_count += 1
            self.current_connection = None
            return CommandResult(returncode=0, stdout="Disconnected", stderr="")
        if cmd == "connect":
            location = args[2]
            protocol = args[3]
            port = args[4] if len(args) > 4 else None
            key = (location, protocol, port)
            self.connect_calls.append(key)
            if self._interrupt_on_connect == key:
                self.current_connection = key
                raise KeyboardInterrupt
            outcome = self._outcomes.get(key)
            if outcome == "timeout":
                return CommandResult(returncode=-1, stdout="", stderr="", timed_out=True)
            if outcome is None or outcome == "connect_fail":
                return CommandResult(returncode=1, stdout="", stderr="Unable to connect")
            self.current_connection = key
            return CommandResult(returncode=0, stdout=f"Connected to {location}", stderr="")
        return CommandResult(returncode=0, stdout="", stderr="")

    def probe(self, url: str, *, timeout: float) -> ProbeResult:
        if self.current_connection is None:
            return ProbeResult(reachable=False, error="not connected")
        if self._interrupt_on_probe == self.current_connection:
            raise KeyboardInterrupt
        outcome = self._outcomes.get(self.current_connection)
        if outcome == "dead_tunnel":
            return ProbeResult(reachable=False, error="tunnel unreachable")
        if isinstance(outcome, list):
            if outcome:
                latency = float(outcome[0])
                if len(outcome) > 1:
                    outcome.pop(0)
                return ProbeResult(reachable=True, latency_ms=latency)
        return ProbeResult(reachable=False, error="no probe outcome")


def _make_dummy_cli(tmpdir: str) -> str:
    cli_path = Path(tmpdir) / "windscribe-cli.exe"
    cli_path.write_text("", encoding="utf-8")
    return str(cli_path)


class TestRegionAndProtocolFiltering(unittest.TestCase):
    def test_regions_and_protocols_filters_are_case_insensitive_across_all_phases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            profile_path = Path(tmpdir) / "profiles.json"

            # Seed saved profile with an entry outside the requested region and one outside requested protocol
            store = ProfileStore(profile_path)
            store.record_attempt(
                "Irancell",
                "off",
                AttemptResult(
                    location="Switzerland",
                    protocol="stealth",
                    port="8443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=40.0,
                ),
            )
            store.record_attempt(
                "Irancell",
                "off",
                AttemptResult(
                    location="Germany - Frankfurt",
                    protocol="wireguard",
                    port="443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=50.0,
                ),
            )

            env = FakeVpnEnv(
                locations_output="\n".join(
                    [
                        "Germany - Frankfurt (10 Gbps)",
                        "Germany - Berlin (Pro)",
                        "Netherlands (Pro)",
                        "Switzerland",
                    ]
                ),
                ports_by_protocol={
                    "wireguard": "443\n",
                    "stealth": "8443\n",
                },
                outcomes={
                    ("Germany - Frankfurt", "stealth", "8443"): [90.0, 110.0],
                    ("Germany - Berlin", "stealth", "8443"): [70.0, 90.0],
                    ("Netherlands", "stealth", "8443"): [50.0, 50.0],
                    ("Switzerland", "stealth", "8443"): [40.0, 40.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()

            rc = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(profile_path),
                    "--isp",
                    "Irancell",
                    "--mode",
                    "off",
                    "--regions",
                    "gErMaNy",
                    "--protocols",
                    "STEALTH",
                    "--probe-locations",
                    "1",
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            # Only Germany locations with stealth protocol should ever be tested
            self.assertEqual(
                env.connect_calls,
                [
                    ("Germany - Frankfurt", "stealth", "8443"),
                    ("Germany - Berlin", "stealth", "8443"),
                ],
            )
            output = out.getvalue()
            self.assertIn("Germany - Berlin", output)
            self.assertIn("Germany - Frankfurt", output)
            self.assertNotIn("Netherlands", output)
            self.assertNotIn("Switzerland", output)

    def test_regions_filter_with_no_matches_returns_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"wireguard": "443\n"},
                outcomes={},
            )
            out = io.StringIO()
            err = io.StringIO()

            rc = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--regions",
                    "Japan,Singapore",
                    "--protocols",
                    "wireguard",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 1)
            self.assertEqual(env.connect_calls, [])
            self.assertIn("No locations matched", out.getvalue())

    def test_discover_only_runs_phase1_and_skips_phase2_sweep(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\nFrance\n",
                ports_by_protocol={
                    "wireguard": "443\n",
                    "stealth": "8443\n",
                },
                outcomes={
                    ("Germany", "wireguard", "443"): "timeout",
                    ("Germany", "stealth", "8443"): [80.0, 80.0],
                    ("Netherlands", "stealth", "8443"): [50.0, 50.0],
                    ("Switzerland", "stealth", "8443"): [60.0, 60.0],
                    ("France", "stealth", "8443"): [70.0, 70.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()

            rc = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--discover-only",
                    "--protocols",
                    "wireguard,stealth",
                    "--probe-locations",
                    "1",
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            # Only Phase 1 probe location (Germany) should be tested; Phase 2 locations skipped
            self.assertEqual(
                env.connect_calls,
                [
                    ("Germany", "wireguard", "443"),
                    ("Germany", "stealth", "8443"),
                ],
            )
            output = out.getvalue()
            self.assertIn("Phase 1: Protocol & Port Discovery", output)
            self.assertNotIn("Phase 2: Location Sweep", output)
            self.assertIn("stealth:8443", output)

    def test_regions_filter_matches_sectioned_and_tabular_locations_output(self) -> None:
        sectioned_output = "\n".join(
            [
                "Germany:",
                "  Frankfurt (10 Gbps)",
                "  Berlin (Pro)",
                "Netherlands:",
                "  Amsterdam (Pro)",
            ]
        )
        tabular_output = "\n".join(
            [
                "Location        Short Name      City            Label",
                "----------------------------------------------------------",
                "Germany         DE              Frankfurt       Castle (10 Gbps)",
                "Germany         DE              Berlin          Wall (Pro)",
                "Netherlands     NL              Amsterdam       Canal (Pro)",
            ]
        )

        for label, locations_output in (("sectioned", sectioned_output), ("tabular", tabular_output)):
            with self.subTest(format=label), tempfile.TemporaryDirectory() as tmpdir:
                cli_path = _make_dummy_cli(tmpdir)
                env = FakeVpnEnv(
                    locations_output=locations_output,
                    ports_by_protocol={"stealth": "8443\n"},
                    outcomes={
                        ("Germany - Frankfurt", "stealth", "8443"): [80.0, 90.0],
                        ("Germany - Berlin", "stealth", "8443"): [60.0, 70.0],
                        ("Netherlands - Amsterdam", "stealth", "8443"): [40.0, 40.0],
                    },
                )
                out = io.StringIO()
                err = io.StringIO()

                rc = main(
                    [
                        "--cli-path",
                        cli_path,
                        "--profile-path",
                        str(Path(tmpdir) / "profiles.json"),
                        "--regions",
                        "Germany",
                        "--protocols",
                        "stealth",
                        "--probe-locations",
                        "1",
                        "--probe-samples",
                        "2",
                    ],
                    runner=env,
                    probe=env,
                    stdout=out,
                    stderr=err,
                )

                self.assertEqual(rc, 0, msg=err.getvalue())
                self.assertEqual(
                    env.connect_calls,
                    [
                        ("Germany - Frankfurt", "stealth", "8443"),
                        ("Germany - Berlin", "stealth", "8443"),
                    ],
                )
                self.assertNotIn("Netherlands", out.getvalue())


class TestGracefulInterruptHandling(unittest.TestCase):
    def test_ctrl_c_during_phase2_disconnects_saves_winners_and_prints_partial_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            profile_path = Path(tmpdir) / "profiles.json"
            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"stealth": "8443\n"},
                outcomes={
                    ("Germany", "stealth", "8443"): [75.0, 85.0],
                    ("Netherlands", "stealth", "8443"): [50.0, 50.0],
                    ("Switzerland", "stealth", "8443"): [90.0, 90.0],
                },
                interrupt_on_probe=("Netherlands", "stealth", "8443"),
            )
            out = io.StringIO()
            err = io.StringIO()

            rc = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(profile_path),
                    "--isp",
                    "MCI",
                    "--mode",
                    "off",
                    "--scan",
                    "--protocols",
                    "stealth",
                    "--probe-locations",
                    "1",
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 130)
            self.assertIsNone(env.current_connection)
            self.assertGreaterEqual(env.disconnect_count, 2)
            # Switzerland should never have been attempted after interrupt on Netherlands
            self.assertNotIn(("Switzerland", "stealth", "8443"), env.connect_calls)

            # Previously discovered winning result must be persisted on disk
            reloaded = ProfileStore(profile_path)
            saved = reloaded.get_entries("MCI", "off")
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0].location, "Germany")
            self.assertEqual(saved[0].protocol, "stealth")
            self.assertEqual(saved[0].port, "8443")

            output = out.getvalue()
            self.assertIn("interrupted", output.lower())
            self.assertIn("Germany", output)
            self.assertIn("80.0 ms", output)

    def test_ctrl_c_during_phase1_connect_disconnects_and_returns_interrupted_scan_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(profile_path)
            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"stealth": "8443\n", "wireguard": "443\n"},
                outcomes={
                    ("Germany", "stealth", "8443"): [60.0, 60.0],
                    ("Germany", "wireguard", "443"): [50.0, 50.0],
                },
                interrupt_on_connect=("Germany", "wireguard", "443"),
            )
            client = WindscribeClient(env, "windscribe-cli.exe")
            out = io.StringIO()

            result = run_smart_scan(
                client,
                env,
                protocols=("stealth", "wireguard"),
                probe_locations=1,
                probe_samples=2,
                profile_store=store,
                isp="Shatel",
                mode="awg",
                output=out,
            )

            self.assertTrue(result.interrupted)
            self.assertIsNone(env.current_connection)
            self.assertEqual(len(result.results), 1)
            self.assertEqual(result.results[0].location, "Germany")
            reloaded = ProfileStore(profile_path)
            self.assertEqual(len(reloaded.get_entries("Shatel", "awg")), 1)


class TestShowProfilesFlag(unittest.TestCase):
    def test_show_profiles_reports_empty_store_without_requiring_windscribe_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            out = io.StringIO()
            err = io.StringIO()

            rc = main(
                [
                    "--profile-path",
                    str(profile_path),
                    "--show-profiles",
                ],
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            self.assertIn("No saved profiles found.", out.getvalue())

    def test_show_profiles_displays_saved_entries_by_isp_and_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(profile_path)
            store.record_attempt(
                "Irancell",
                "amneziawg-1",
                AttemptResult(
                    location="Netherlands",
                    protocol="stealth",
                    port="8443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=52.3,
                ),
            )
            store.record_attempt(
                "Shatel",
                "off",
                AttemptResult(
                    location="Germany",
                    protocol="wireguard",
                    port="443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=68.0,
                ),
            )
            out = io.StringIO()
            err = io.StringIO()

            rc = main(
                [
                    "--profile-path",
                    str(profile_path),
                    "--show-profiles",
                ],
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            output = out.getvalue()
            self.assertIn("Irancell", output)
            self.assertIn("amneziawg-1", output)
            self.assertIn("Netherlands", output)
            self.assertIn("stealth", output)
            self.assertIn("8443", output)
            self.assertIn("52.3 ms", output)
            self.assertIn("Shatel", output)
            self.assertIn("Germany", output)


class TestInteractiveMenu(unittest.TestCase):
    def test_no_arguments_launches_interactive_menu_and_exits_cleanly(self) -> None:
        out = io.StringIO()
        err = io.StringIO()

        rc = main(
            [],
            stdin=io.StringIO("6\n"),
            stdout=out,
            stderr=err,
        )

        self.assertEqual(rc, 0, msg=err.getvalue())
        output = out.getvalue()
        self.assertIn("Quick Connect", output)
        self.assertIn("Smart Scan", output)
        self.assertIn("Protocol", output)
        self.assertIn("View Saved Profiles", output)
        self.assertIn("View AmneziaWG Presets", output)
        self.assertIn("Exit", output)

    def test_interactive_menu_quick_connect_uses_saved_profiles_and_stays_connected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            profile_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(profile_path)
            store.record_attempt(
                "Irancell",
                "off",
                AttemptResult(
                    location="Netherlands",
                    protocol="stealth",
                    port="8443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=48.0,
                ),
            )
            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"stealth": "8443\n"},
                outcomes={
                    ("Netherlands", "stealth", "8443"): [45.0, 55.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()
            # Choice 1 (Quick Connect) -> ISP=Irancell, Mode=off, Regions="" -> Choice 6 (Exit)
            user_input = io.StringIO("1\nIrancell\noff\n\n6\n")

            rc = main(
                [
                    "--interactive",
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(profile_path),
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdin=user_input,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            self.assertEqual(env.connect_calls, [("Netherlands", "stealth", "8443")])
            self.assertEqual(env.current_connection, ("Netherlands", "stealth", "8443"))
            self.assertIn("Phase 0: Saved Profile Fast-Path", out.getvalue())

    def test_interactive_menu_smart_scan_and_protocol_discovery_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            profile_path = Path(tmpdir) / "profiles.json"
            env = FakeVpnEnv(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"wireguard": "443\n", "stealth": "8443\n"},
                outcomes={
                    ("Germany", "stealth", "8443"): [70.0, 70.0],
                    ("Germany", "wireguard", "443"): "timeout",
                    ("Netherlands", "stealth", "8443"): [50.0, 50.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()
            # Choice 2 (Smart Scan): ISP=Shatel, mode=off, regions=germany, protocols=stealth, timeout=10, keep=n
            # Choice 3 (Discovery only): ISP=Shatel, mode=off, regions="", protocols=wireguard,stealth, timeout=""
            # Choice 6 (Exit)
            user_input = io.StringIO(
                "2\nShatel\noff\ngermany\nstealth\n10\nn\n"
                "3\nShatel\noff\n\nwireguard,stealth\n\n"
                "6\n"
            )

            rc = main(
                [
                    "--interactive",
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(profile_path),
                    "--probe-locations",
                    "1",
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdin=user_input,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            # Smart Scan tested Germany/stealth; Discovery tested Germany/wireguard + Germany/stealth (no Phase 2 sweep of Netherlands/Switzerland)
            self.assertNotIn(("Netherlands", "stealth", "8443"), env.connect_calls)
            self.assertNotIn(("Switzerland", "stealth", "8443"), env.connect_calls)
            self.assertIn(("Germany", "stealth", "8443"), env.connect_calls)
            self.assertIn(("Germany", "wireguard", "443"), env.connect_calls)

    def test_interactive_menu_views_profiles_presets_and_handles_invalid_choice(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = _make_dummy_cli(tmpdir)
            profile_path = Path(tmpdir) / "profiles.json"
            store = ProfileStore(profile_path)
            store.record_attempt(
                "MCI",
                "preset-1",
                AttemptResult(
                    location="Frankfurt",
                    protocol="wstunnel",
                    port="443",
                    connected=True,
                    healthy=True,
                    avg_latency_ms=61.5,
                ),
            )
            env = FakeVpnEnv(
                amneziawg_output="Available presets:\n- preset-1\n- preset-2\n",
            )
            out = io.StringIO()
            err = io.StringIO()
            user_input = io.StringIO("99\n4\n5\n6\n")

            rc = main(
                [
                    "--interactive",
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(profile_path),
                ],
                runner=env,
                probe=env,
                stdin=user_input,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(rc, 0, msg=err.getvalue())
            output = out.getvalue()
            self.assertIn("Invalid choice", output)
            self.assertIn("MCI", output)
            self.assertIn("Frankfurt", output)
            self.assertIn("preset-1", output)
            self.assertIn("preset-2", output)


if __name__ == "__main__":
    unittest.main()
