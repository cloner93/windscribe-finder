from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from windscribe_finder.cli import main
from windscribe_finder.models import CommandResult, ProbeResult, ProtocolPort, WindscribeNotReadyError
from windscribe_finder.scanner import run_smart_scan
from windscribe_finder.windscribe import WindscribeClient


class FakeCommandRunner:
    def __init__(self, handler=None) -> None:
        self._handler = handler
        self.calls: list[tuple[list[str], float | None]] = []

    def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
        self.calls.append((list(args), timeout))
        if self._handler is not None:
            return self._handler(list(args), timeout)
        return CommandResult(returncode=0, stdout="", stderr="")


class TestLocationsParsing(unittest.TestCase):
    def test_parses_pro_and_10gbps_locations_and_skips_disabled(self) -> None:
        raw_locations = "\n".join(
            [
                "US Central",
                "Germany (10 Gbps)",
                "Netherlands (Pro)",
                "Switzerland (Pro) (10 Gbps)",
                "Turkey (Disabled)",
                "Russia (Pro) (Disabled)",
                "Germany (10 Gbps)",
            ]
        )
        runner = FakeCommandRunner(
            lambda args, timeout: CommandResult(returncode=0, stdout=raw_locations, stderr="")
        )
        client = WindscribeClient(runner, "windscribe-cli.exe")

        locations = client.list_locations()

        self.assertEqual(
            locations,
            ["US Central", "Germany", "Netherlands", "Switzerland"],
        )
        self.assertEqual(runner.calls[0][0], ["windscribe-cli.exe", "locations"])

    def test_parses_sectioned_and_tabular_locations_output(self) -> None:
        sectioned_output = "\n".join(
            [
                "Germany:",
                "  Frankfurt (10 Gbps)",
                "  Berlin (Pro)",
                "Turkey (Disabled):",
                "  Istanbul",
                "Netherlands:",
                "  Amsterdam (Pro) (10 Gbps)",
                "  Rotterdam (Disabled)",
            ]
        )
        runner = FakeCommandRunner(
            lambda args, timeout: CommandResult(returncode=0, stdout=sectioned_output, stderr="")
        )
        client = WindscribeClient(runner, "windscribe-cli.exe")

        self.assertEqual(
            client.list_locations(),
            ["Germany - Frankfurt", "Germany - Berlin", "Netherlands - Amsterdam"],
        )

        tabular_output = "\n".join(
            [
                "Location        Short Name      City            Label",
                "----------------------------------------------------------",
                "Germany         DE              Frankfurt       Castle (10 Gbps)",
                "Netherlands     NL              Amsterdam       Canal (Pro)",
                "Turkey          TR              Istanbul        Ataturk (Disabled)",
            ]
        )
        runner2 = FakeCommandRunner(
            lambda args, timeout: CommandResult(returncode=0, stdout=tabular_output, stderr="")
        )
        client2 = WindscribeClient(runner2, "windscribe-cli.exe")

        self.assertEqual(
            client2.list_locations(),
            ["Germany - Frankfurt", "Netherlands - Amsterdam"],
        )

    def test_list_locations_raises_when_desktop_not_running(self) -> None:
        runner = FakeCommandRunner(
            lambda args, timeout: CommandResult(
                returncode=1,
                stdout="",
                stderr="Windscribe application is not running.",
            )
        )
        client = WindscribeClient(runner, "windscribe-cli.exe")

        with self.assertRaises(WindscribeNotReadyError):
            client.list_locations()


class TestPortsParsing(unittest.TestCase):
    def test_queries_valid_ports_dynamically_for_protocol(self) -> None:
        responses = {
            "wireguard": CommandResult(returncode=0, stdout="443\n80\n53\n1194\n443\n", stderr=""),
            "stealth": CommandResult(
                returncode=0,
                stdout="Available ports for stealth: 443, 8443, 587, 99999, 0",
                stderr="",
            ),
            "ikev2": CommandResult(returncode=0, stdout="", stderr=""),
        }
        runner = FakeCommandRunner(lambda args, timeout: responses[args[2]])
        client = WindscribeClient(runner, "windscribe-cli.exe")

        self.assertEqual(client.list_ports("wireguard"), ["443", "80", "53", "1194"])
        self.assertEqual(client.list_ports("stealth"), ["443", "8443", "587"])
        self.assertEqual(client.list_ports("ikev2"), [])
        self.assertEqual(
            [args for args, _ in runner.calls],
            [
                ["windscribe-cli.exe", "ports", "wireguard"],
                ["windscribe-cli.exe", "ports", "stealth"],
                ["windscribe-cli.exe", "ports", "ikev2"],
            ],
        )

    def test_list_ports_raises_when_desktop_not_logged_in(self) -> None:
        runner = FakeCommandRunner(
            lambda args, timeout: CommandResult(
                returncode=1,
                stdout="",
                stderr="Please log in to Windscribe first.",
            )
        )
        client = WindscribeClient(runner, "windscribe-cli.exe")

        with self.assertRaises(WindscribeNotReadyError):
            client.list_ports("wireguard")


class FakeVpnEnvironment:
    """Simulated Windscribe CLI + network environment behind the two outermost seams."""

    def __init__(
        self,
        *,
        locations_output: str,
        ports_by_protocol: dict[str, str],
        outcomes: dict[tuple[str, str, str | None], str | list[float]],
    ) -> None:
        self.locations_output = locations_output
        self.ports_by_protocol = dict(ports_by_protocol)
        # outcomes values: "timeout", "connect_fail", "dead_tunnel", or list of latency_ms samples
        self.outcomes = dict(outcomes)
        self.current_connection: tuple[str, str, str | None] | None = None
        self.connect_calls: list[tuple[str, str, str | None]] = []
        self.command_calls: list[list[str]] = []
        self._sample_cursor: int = 0

    def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
        self.command_calls.append(list(args))
        cmd = args[1]
        if cmd == "status":
            state = f"Connected to {self.current_connection[0]}" if self.current_connection else "Disconnected"
            return CommandResult(returncode=0, stdout=f"Connect state: {state}", stderr="")
        if cmd == "locations":
            return CommandResult(returncode=0, stdout=self.locations_output, stderr="")
        if cmd == "ports":
            proto = args[2]
            stdout = self.ports_by_protocol.get(proto, "")
            return CommandResult(returncode=0, stdout=stdout, stderr="")
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


class TestTwoPhaseSmartScanner(unittest.TestCase):
    def test_phase1_filters_blocked_pairs_and_phase2_sweeps_and_ranks_by_latency(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="\n".join(
                [
                    "Germany (10 Gbps)",
                    "Netherlands (Pro)",
                    "Switzerland (Pro) (10 Gbps)",
                    "France",
                    "Turkey (Disabled)",
                ]
            ),
            ports_by_protocol={
                "wireguard": "443\n80\n",
                "stealth": "443\n",
            },
            outcomes={
                # wireguard:443 is completely blocked (timeout / dead tunnel) on sample locations
                ("Germany", "wireguard", "443"): "timeout",
                ("Netherlands", "wireguard", "443"): "dead_tunnel",
                # wireguard:80 works!
                ("Germany", "wireguard", "80"): [140.0, 160.0],
                ("Netherlands", "wireguard", "80"): [90.0, 110.0],
                ("Switzerland", "wireguard", "80"): [60.0, 70.0],
                ("France", "wireguard", "80"): "dead_tunnel",
                # stealth:443 works on Netherlands (fails on Germany)
                ("Germany", "stealth", "443"): "connect_fail",
                ("Netherlands", "stealth", "443"): [115.0, 125.0],
                ("Switzerland", "stealth", "443"): [45.0, 55.0],
                ("France", "stealth", "443"): [190.0, 210.0],
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
            output=out,
        )

        # Phase 1 discovered wireguard:80 and stealth:443, and filtered out wireguard:443
        self.assertEqual(
            scan_result.working_pairs,
            (
                ProtocolPort("wireguard", "80"),
                ProtocolPort("stealth", "443"),
            ),
        )
        # Blocked pair wireguard:443 must NEVER be tested on Phase 2 locations (Switzerland, France)
        self.assertNotIn(("Switzerland", "wireguard", "443"), env.connect_calls)
        self.assertNotIn(("France", "wireguard", "443"), env.connect_calls)
        # Disabled location Turkey must NEVER be tested
        self.assertTrue(all(loc != "Turkey" for loc, _, _ in env.connect_calls))
        # Already-tested (location, protocol, port) pairs from Phase 1 are not redundantly re-tested
        self.assertEqual(len(env.connect_calls), len(set(env.connect_calls)))

        # Ranked results sorted by lowest average latency
        ranked_summary = [
            (r.location, r.protocol, r.port, r.avg_latency_ms)
            for r in scan_result.results
        ]
        self.assertEqual(
            ranked_summary,
            [
                ("Switzerland", "stealth", "443", 50.0),
                ("Switzerland", "wireguard", "80", 65.0),
                ("Netherlands", "wireguard", "80", 100.0),
                ("Netherlands", "stealth", "443", 120.0),
                ("Germany", "wireguard", "80", 150.0),
                ("France", "stealth", "443", 200.0),
            ],
        )
        # Default keep_connected=False leaves Windscribe disconnected
        self.assertIsNone(env.current_connection)
        self.assertIsNone(scan_result.connected_result)

    def test_quick_mode_stops_on_first_healthy_connection(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="Germany\nNetherlands\nSwitzerland\n",
            ports_by_protocol={"wireguard": "443\n80\n", "stealth": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): "timeout",
                ("Netherlands", "wireguard", "443"): [85.0, 95.0],
                ("Germany", "wireguard", "80"): [40.0, 40.0],
                ("Switzerland", "wireguard", "443"): [30.0, 30.0],
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
            quick=True,
            keep_connected=False,
            output=out,
        )

        self.assertEqual(
            env.connect_calls,
            [
                ("Germany", "wireguard", "443"),
                ("Netherlands", "wireguard", "443"),
            ],
        )
        self.assertEqual(len(scan_result.results), 1)
        self.assertEqual(scan_result.results[0].location, "Netherlands")
        self.assertIsNone(env.current_connection)
        self.assertIsNone(scan_result.connected_result)

    def test_quick_mode_with_keep_connected_stays_connected_without_reconnecting(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="Germany\nNetherlands\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): [70.0, 80.0],
                ("Netherlands", "wireguard", "443"): [30.0, 30.0],
            },
        )
        client = WindscribeClient(env, "windscribe-cli.exe")
        out = io.StringIO()

        scan_result = run_smart_scan(
            client,
            env,
            protocols=("wireguard",),
            probe_locations=2,
            probe_samples=2,
            quick=True,
            keep_connected=True,
            output=out,
        )

        self.assertEqual(env.connect_calls, [("Germany", "wireguard", "443")])
        self.assertEqual(env.current_connection, ("Germany", "wireguard", "443"))
        self.assertIsNotNone(scan_result.connected_result)
        assert scan_result.connected_result is not None
        self.assertEqual(scan_result.connected_result.location, "Germany")
        # Never disconnected after connecting to the healthy server
        disconnect_calls = [c for c in env.command_calls if c[1] == "disconnect"]
        self.assertEqual(disconnect_calls, [])

    def test_keep_connected_after_full_scan_connects_to_top_ranked_server(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="Germany\nNetherlands\nSwitzerland\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): [150.0, 150.0],
                ("Netherlands", "wireguard", "443"): [50.0, 50.0],
                ("Switzerland", "wireguard", "443"): [90.0, 90.0],
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
            keep_connected=True,
            output=out,
        )

        self.assertEqual(scan_result.results[0].location, "Netherlands")
        self.assertEqual(env.current_connection, ("Netherlands", "wireguard", "443"))
        self.assertEqual(scan_result.connected_result, scan_result.results[0])

    def test_all_blocked_scan_skips_phase2_and_stays_disconnected(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="Germany\nNetherlands\nSwitzerland\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): "timeout",
                ("Netherlands", "wireguard", "443"): "dead_tunnel",
            },
        )
        client = WindscribeClient(env, "windscribe-cli.exe")
        out = io.StringIO()

        scan_result = run_smart_scan(
            client,
            env,
            protocols=("wireguard",),
            probe_locations=2,
            probe_samples=2,
            keep_connected=True,
            output=out,
        )

        self.assertEqual(scan_result.working_pairs, ())
        self.assertEqual(scan_result.results, ())
        self.assertIsNone(scan_result.connected_result)
        self.assertIsNone(env.current_connection)
        self.assertNotIn(("Switzerland", "wireguard", "443"), env.connect_calls)
        self.assertIn("No working connections found.", out.getvalue())

    def test_quick_mode_stays_connected_by_default(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="Germany\nNetherlands\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): [65.0, 75.0],
                ("Netherlands", "wireguard", "443"): [30.0, 30.0],
            },
        )
        client = WindscribeClient(env, "windscribe-cli.exe")
        out = io.StringIO()

        scan_result = run_smart_scan(
            client,
            env,
            protocols=("wireguard",),
            probe_locations=2,
            probe_samples=2,
            quick=True,
            output=out,
        )

        self.assertEqual(env.connect_calls, [("Germany", "wireguard", "443")])
        self.assertEqual(env.current_connection, ("Germany", "wireguard", "443"))
        self.assertIsNotNone(scan_result.connected_result)
        assert scan_result.connected_result is not None
        self.assertEqual(scan_result.connected_result.location, "Germany")
        disconnect_calls = [c for c in env.command_calls if c[1] == "disconnect"]
        self.assertEqual(disconnect_calls, [])

    def test_keep_connected_falls_back_to_next_ranked_server_when_top_reconnect_fails(self) -> None:
        class FlakyReconnectEnv(FakeVpnEnvironment):
            def __init__(self, fail_second_connect_for: set[tuple[str, str, str | None]], **kwargs) -> None:
                super().__init__(**kwargs)
                self._fail_second_connect_for = fail_second_connect_for
                self._connect_counts: dict[tuple[str, str, str | None], int] = {}

            def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
                if args[1] == "connect":
                    proto_spec = args[3]
                    protocol, port = proto_spec.split(":", 1) if ":" in proto_spec else (proto_spec, None)
                    key = (args[2], protocol, port)
                    self._connect_counts[key] = self._connect_counts.get(key, 0) + 1
                    if self._connect_counts[key] >= 2 and key in self._fail_second_connect_for:
                        self.command_calls.append(list(args))
                        self.connect_calls.append(key)
                        return CommandResult(returncode=-1, stdout="", stderr="", timed_out=True)
                return super().run(args, timeout=timeout)

        env = FlakyReconnectEnv(
            fail_second_connect_for={("Netherlands", "wireguard", "443")},
            locations_output="Germany\nNetherlands\nSwitzerland\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): [150.0, 150.0],
                ("Netherlands", "wireguard", "443"): [50.0, 50.0],
                ("Switzerland", "wireguard", "443"): [90.0, 90.0],
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
            keep_connected=True,
            output=out,
        )

        # Ranked order: Netherlands (50ms), Switzerland (90ms), Germany (150ms)
        self.assertEqual(scan_result.results[0].location, "Netherlands")
        # Top reconnect failed -> fell back to #2 (Switzerland)
        self.assertEqual(env.current_connection, ("Switzerland", "wireguard", "443"))
        self.assertEqual(scan_result.connected_result, scan_result.results[1])
        output = out.getvalue()
        self.assertIn("Warning: failed to reconnect to Netherlands [wireguard:443]", output)
        self.assertIn("Falling back to ranked server #2: Switzerland [wireguard:443]", output)

    def test_keep_connected_emits_clear_error_when_all_ranked_reconnects_fail(self) -> None:
        class AllReconnectsFailEnv(FakeVpnEnvironment):
            def __init__(self, **kwargs) -> None:
                super().__init__(**kwargs)
                self._connect_counts: dict[tuple[str, str, str | None], int] = {}

            def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
                if args[1] == "connect":
                    proto_spec = args[3]
                    protocol, port = proto_spec.split(":", 1) if ":" in proto_spec else (proto_spec, None)
                    key = (args[2], protocol, port)
                    self._connect_counts[key] = self._connect_counts.get(key, 0) + 1
                    if self._connect_counts[key] >= 2:
                        self.command_calls.append(list(args))
                        self.connect_calls.append(key)
                        return CommandResult(returncode=1, stdout="", stderr="Failed to connect")
                return super().run(args, timeout=timeout)

        env = AllReconnectsFailEnv(
            locations_output="Germany\nNetherlands\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany", "wireguard", "443"): [100.0, 100.0],
                ("Netherlands", "wireguard", "443"): [50.0, 50.0],
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
            keep_connected=True,
            output=out,
        )

        self.assertIsNone(scan_result.connected_result)
        self.assertIsNone(env.current_connection)
        output = out.getvalue()
        self.assertIn("Warning: failed to reconnect to Netherlands [wireguard:443]", output)
        self.assertIn("Warning: failed to reconnect to Germany [wireguard:443]", output)
        self.assertIn("Error: failed to reconnect to any ranked server.", output)

    def test_phase1_picks_diverse_regions_rather_than_two_cities_in_same_country(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="\n".join(
                [
                    "Germany - Frankfurt (10 Gbps)",
                    "Germany - Berlin (Pro)",
                    "Netherlands - Amsterdam (Pro)",
                    "Switzerland - Zurich",
                ]
            ),
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Germany - Frankfurt", "wireguard", "443"): "timeout",
                ("Netherlands - Amsterdam", "wireguard", "443"): "timeout",
            },
        )
        client = WindscribeClient(env, "windscribe-cli.exe")
        out = io.StringIO()

        run_smart_scan(
            client,
            env,
            protocols=("wireguard",),
            probe_locations=2,
            probe_samples=1,
            discover_only=True,
            output=out,
        )

        self.assertEqual(
            env.connect_calls,
            [
                ("Frankfurt", "wireguard", "443"),
                ("Amsterdam", "wireguard", "443"),
            ],
        )

    def test_phase1_falls_back_to_same_country_when_fewer_distinct_regions_exist(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="Germany - Frankfurt\nGermany - Berlin\n",
            ports_by_protocol={"wireguard": "443\n"},
            outcomes={
                ("Frankfurt", "wireguard", "443"): "timeout",
                ("Berlin", "wireguard", "443"): "timeout",
            },
        )
        client = WindscribeClient(env, "windscribe-cli.exe")
        out = io.StringIO()

        run_smart_scan(
            client,
            env,
            protocols=("wireguard",),
            probe_locations=2,
            probe_samples=1,
            discover_only=True,
            output=out,
        )

        self.assertEqual(
            env.connect_calls,
            [
                ("Frankfurt", "wireguard", "443"),
                ("Berlin", "wireguard", "443"),
            ],
        )

    def test_strips_spdlog_noise_from_ports_and_connect_and_extracts_nickname_or_best(self) -> None:
        env = FakeVpnEnvironment(
            locations_output="\n".join(
                [
                    "spdlog init failed: rotating_file_sink: failed renaming cli.log to cli.1.log: permission denied",
                    "Best Location - Alphorn (10 Gbps)",
                    "US Central - Atlanta - Magic City (10 Gbps)",
                ]
            ),
            ports_by_protocol={
                "wireguard": (
                    "spdlog init failed: rotating_file_sink: failed renaming cli.log to cli.1.log: permission denied\n"
                    "443, 80, 53\n"
                ),
            },
            outcomes={
                ("best", "wireguard", "443"): "timeout",
                ("Magic City", "wireguard", "443"): [65.0, 75.0],
            },
        )
        original_run = env.run

        def run_with_spdlog_stderr(args: list[str], *, timeout: float | None = None) -> CommandResult:
            res = original_run(args, timeout=timeout)
            if args[1] == "connect" and res.returncode == 0:
                return CommandResult(
                    returncode=0,
                    stdout=res.stdout,
                    stderr="spdlog init failed: rotating_file_sink: failed renaming cli.log to cli.1.log: permission denied",
                )
            return res

        env.run = run_with_spdlog_stderr  # type: ignore[method-assign]
        client = WindscribeClient(env, "windscribe-cli.exe")
        out = io.StringIO()

        result = run_smart_scan(
            client,
            env,
            protocols=("wireguard",),
            probe_locations=2,
            probe_samples=2,
            quick=True,
            output=out,
        )

        # Port "1" from cli.1.log must NOT be parsed as a port
        self.assertEqual(
            env.connect_calls,
            [
                ("best", "wireguard", "443"),
                ("Magic City", "wireguard", "443"),
            ],
        )
        self.assertEqual(len(result.results), 1)
        self.assertEqual(result.results[0].location, "US Central - Atlanta - Magic City")
        self.assertEqual(result.results[0].port, "443")


class TestCliSmartScan(unittest.TestCase):
    def _create_dummy_cli(self, tmpdir: str) -> str:
        cli_exe = Path(tmpdir) / "windscribe-cli.exe"
        cli_exe.write_text("", encoding="utf-8")
        return str(cli_exe)

    def test_cli_scan_prints_live_progress_and_ranked_summary_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            env = FakeVpnEnvironment(
                locations_output="Germany (10 Gbps)\nNetherlands (Pro)\nSwitzerland (Pro)\n",
                ports_by_protocol={"wireguard": "443\n", "stealth": "8443\n"},
                outcomes={
                    ("Germany", "wireguard", "443"): "timeout",
                    ("Netherlands", "wireguard", "443"): "timeout",
                    ("Germany", "stealth", "8443"): [130.0, 150.0],
                    ("Netherlands", "stealth", "8443"): [55.0, 65.0],
                    ("Switzerland", "stealth", "8443"): [95.0, 105.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--scan",
                    "--protocols",
                    "wireguard,stealth",
                    "--probe-locations",
                    "2",
                    "--probe-samples",
                    "2",
                    "--keep-connected",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            output = out.getvalue()
            # Live progress lines for both phases
            self.assertIn("Phase 1: Protocol & Port Discovery", output)
            self.assertIn("[Phase 1]", output)
            self.assertIn("Phase 2: Location Sweep", output)
            self.assertIn("[Phase 2]", output)
            # Ranked summary table headers and order (Netherlands 60.0 ms before Switzerland 100.0 ms before Germany 140.0 ms)
            self.assertIn("Rank", output)
            self.assertIn("Avg Latency", output)
            table_start = output.index("Rank")
            table_section = output[table_start:]
            self.assertLess(
                table_section.index("Netherlands"),
                table_section.index("Switzerland"),
            )
            self.assertLess(
                table_section.index("Switzerland"),
                table_section.index("Germany"),
            )
            # Keep-connected connected to the #1 server (Netherlands)
            self.assertEqual(env.current_connection, ("Netherlands", "stealth", "8443"))

    def test_cli_scan_quick_mode_returns_zero_on_first_healthy_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            env = FakeVpnEnvironment(
                locations_output="Germany\nNetherlands\nSwitzerland\n",
                ports_by_protocol={"wireguard": "443\n80\n"},
                outcomes={
                    ("Germany", "wireguard", "443"): [80.0, 80.0],
                    ("Netherlands", "wireguard", "443"): [40.0, 40.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--scan",
                    "--protocols",
                    "wireguard",
                    "--quick",
                    "--keep-connected",
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            self.assertEqual(env.connect_calls, [("Germany", "wireguard", "443")])
            self.assertEqual(env.current_connection, ("Germany", "wireguard", "443"))

    def test_cli_scan_quick_mode_stays_connected_without_keep_connected_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            env = FakeVpnEnvironment(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"wireguard": "443\n"},
                outcomes={
                    ("Germany", "wireguard", "443"): [75.0, 85.0],
                    ("Netherlands", "wireguard", "443"): [40.0, 40.0],
                },
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--scan",
                    "--protocols",
                    "wireguard",
                    "--quick",
                    "--probe-samples",
                    "2",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            self.assertEqual(env.connect_calls, [("Germany", "wireguard", "443")])
            self.assertEqual(env.current_connection, ("Germany", "wireguard", "443"))
            disconnect_calls = [c for c in env.command_calls if c[1] == "disconnect"]
            self.assertEqual(disconnect_calls, [])

    def test_cli_scan_returns_one_when_no_working_connections_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            env = FakeVpnEnvironment(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"wireguard": "443\n"},
                outcomes={},
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--scan",
                    "--protocols",
                    "wireguard",
                    "--probe-locations",
                    "1",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 1)
            self.assertIn("No working connections found.", out.getvalue())

    def test_scan_prints_estimated_max_time_and_phase1_total_counter(self) -> None:
        from windscribe_finder.scanner import format_duration, format_time_estimate

        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(90), "1m 30s")
        self.assertEqual(format_duration(120), "2m")
        self.assertEqual(format_duration(3660), "1h 1m")
        self.assertIn(
            "Estimated max time: up to 1m (4 attempt(s) x 15.0s timeout; stops early on first healthy connection)",
            format_time_estimate(4, 15.0, quick=True),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            env = FakeVpnEnvironment(
                locations_output="Germany\nNetherlands\n",
                ports_by_protocol={"udp": "443, 80\n"},
                outcomes={},
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--profile-path",
                    str(Path(tmpdir) / "profiles.json"),
                    "--scan",
                    "--protocols",
                    "udp",
                    "--timeout",
                    "10",
                    "--quick",
                ],
                runner=env,
                probe=env,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 1)
            output = out.getvalue()
            self.assertIn(
                "Estimated max time: up to 40s (4 attempt(s) x 10.0s timeout; stops early on first healthy connection)",
                output,
            )
            self.assertIn("[Phase 1] [1/4]", output)
            self.assertIn("[Phase 1] [4/4]", output)


if __name__ == "__main__":
    unittest.main()
