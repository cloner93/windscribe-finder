from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from windscribe_finder.cli import main
from windscribe_finder.models import CommandResult, ProbeResult


class FakeCommandRunner:
    def __init__(self, responses: list[CommandResult] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[tuple[list[str], float | None]] = []

    def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
        self.calls.append((list(args), timeout))
        if self.responses:
            return self.responses.pop(0)
        return CommandResult(returncode=0, stdout="Connected", stderr="")


class FakeConnectivityProbe:
    def __init__(self, results: list[ProbeResult] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[tuple[str, float]] = []

    def probe(self, url: str, *, timeout: float) -> ProbeResult:
        self.calls.append((url, timeout))
        if self.results:
            return self.results.pop(0)
        return ProbeResult(reachable=True, latency_ms=50.0)


class TestCliPathDetection(unittest.TestCase):
    def test_auto_detects_windscribe_cli_from_program_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_exe = Path(tmpdir) / "Windscribe" / "windscribe-cli.exe"
            cli_exe.parent.mkdir(parents=True)
            cli_exe.write_text("", encoding="utf-8")

            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Germany", stderr=""),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe(
                results=[
                    ProbeResult(reachable=True, latency_ms=40.0),
                    ProbeResult(reachable=True, latency_ms=60.0),
                    ProbeResult(reachable=True, latency_ms=50.0),
                ]
            )
            out = io.StringIO()
            err = io.StringIO()

            env = {"PROGRAMFILES": tmpdir, "PROGRAMFILES(X86)": "", "LOCALAPPDATA": "", "PATH": ""}
            with mock.patch.dict(os.environ, env, clear=True):
                exit_code = main(
                    ["--location", "Germany", "--protocol", "wireguard"],
                    runner=runner,
                    probe=probe,
                    stdout=out,
                    stderr=err,
                )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            self.assertEqual(runner.calls[0][0][0], str(cli_exe))

    def test_override_cli_path_option_uses_given_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_cli = Path(tmpdir) / "custom-windscribe.exe"
            custom_cli.write_text("", encoding="utf-8")

            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Germany", stderr=""),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    str(custom_cli),
                    "--location",
                    "Germany",
                    "--protocol",
                    "wireguard",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            self.assertEqual(runner.calls[0][0][0], str(custom_cli))

    def test_missing_override_cli_path_returns_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_cli = Path(tmpdir) / "does-not-exist.exe"
            runner = FakeCommandRunner()
            probe = FakeConnectivityProbe()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    str(missing_cli),
                    "--location",
                    "Germany",
                    "--protocol",
                    "wireguard",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertNotEqual(exit_code, 0)
            self.assertIn("not found", err.getvalue().lower())
            self.assertEqual(runner.calls, [])

    def test_missing_auto_detected_cli_returns_actionable_error(self) -> None:
        runner = FakeCommandRunner()
        probe = FakeConnectivityProbe()
        out = io.StringIO()
        err = io.StringIO()

        with tempfile.TemporaryDirectory() as empty_dir:
            env = {
                "PROGRAMFILES": empty_dir,
                "PROGRAMFILES(X86)": empty_dir,
                "LOCALAPPDATA": empty_dir,
                "PATH": empty_dir,
            }
            with mock.patch.dict(os.environ, env, clear=True):
                exit_code = main(
                    ["--location", "Germany", "--protocol", "wireguard"],
                    runner=runner,
                    probe=probe,
                    stdout=out,
                    stderr=err,
                )

        self.assertEqual(exit_code, 2)
        self.assertIn("--cli-path", err.getvalue())
        self.assertEqual(runner.calls, [])


class TestPreflightReadiness(unittest.TestCase):
    def _create_dummy_cli(self, tmpdir: str) -> str:
        cli_exe = Path(tmpdir) / "windscribe-cli.exe"
        cli_exe.write_text("", encoding="utf-8")
        return str(cli_exe)

    def test_desktop_not_running_surfaces_clear_error_and_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(
                        returncode=1,
                        stdout="",
                        stderr="Windscribe application is not running. Please launch Windscribe.",
                    )
                ]
            )
            probe = FakeConnectivityProbe()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                ["--cli-path", cli_path, "--location", "Germany", "--protocol", "wireguard"],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 2)
            self.assertIn("not running", err.getvalue().lower())
            self.assertIn("open windscribe desktop", err.getvalue().lower())
            self.assertEqual(len(runner.calls), 1)
            self.assertEqual(runner.calls[0][0], [cli_path, "status"])
            self.assertEqual(probe.calls, [])

    def test_desktop_not_logged_in_surfaces_clear_error_and_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(
                        returncode=0,
                        stdout="Account: Not logged in",
                        stderr="",
                    )
                ]
            )
            probe = FakeConnectivityProbe()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                ["--cli-path", cli_path, "--location", "Germany", "--protocol", "wireguard"],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 2)
            self.assertIn("not logged in", err.getvalue().lower())
            self.assertEqual(len(runner.calls), 1)
            self.assertEqual(probe.calls, [])

    def test_status_timeout_surfaces_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[CommandResult(returncode=-1, stdout="", stderr="", timed_out=True)]
            )
            probe = FakeConnectivityProbe()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                ["--cli-path", cli_path, "--location", "Germany", "--protocol", "wireguard"],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 2)
            self.assertIn("timed out", err.getvalue().lower())
            self.assertEqual(probe.calls, [])


class TestSingleAttemptFlow(unittest.TestCase):
    def _create_dummy_cli(self, tmpdir: str) -> str:
        cli_exe = Path(tmpdir) / "windscribe-cli.exe"
        cli_exe.write_text("", encoding="utf-8")
        return str(cli_exe)

    def test_connects_with_port_measures_avg_latency_and_disconnects(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Germany", stderr=""),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe(
                results=[
                    ProbeResult(reachable=True, latency_ms=100.0),
                    ProbeResult(reachable=True, latency_ms=140.0),
                    ProbeResult(reachable=True, latency_ms=120.0),
                ]
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--location",
                    "Germany",
                    "--protocol",
                    "stealth",
                    "--port",
                    "443",
                    "--timeout",
                    "12",
                    "--probe-timeout",
                    "4",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0, msg=err.getvalue())
            self.assertEqual(
                [args for args, _ in runner.calls],
                [
                    [cli_path, "status"],
                    [cli_path, "connect", "Germany", "stealth:443"],
                    [cli_path, "disconnect"],
                ],
            )
            self.assertEqual(runner.calls[1][1], 12.0)
            self.assertEqual(len(probe.calls), 3)
            self.assertTrue(all(timeout == 4.0 for _, timeout in probe.calls))
            self.assertIn("OK Germany [stealth:443] - avg latency 120.0 ms", out.getvalue())

    def test_connect_timeout_disconnects_cleanly_and_skips_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=-1, stdout="", stderr="", timed_out=True),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe()
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--location",
                    "Germany",
                    "--protocol",
                    "wireguard",
                    "--timeout",
                    "8",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 1)
            self.assertEqual(
                [args for args, _ in runner.calls],
                [
                    [cli_path, "status"],
                    [cli_path, "connect", "Germany", "wireguard"],
                    [cli_path, "disconnect"],
                ],
            )
            self.assertEqual(probe.calls, [])
            self.assertIn("TIMEOUT", out.getvalue())

    def test_connected_but_dead_tunnel_is_rejected_and_disconnected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Frankfurt", stderr=""),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe(
                results=[
                    ProbeResult(reachable=False, error="timed out"),
                    ProbeResult(reachable=False, error="connection reset"),
                ]
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--location",
                    "Frankfurt",
                    "--protocol",
                    "wstunnel",
                    "--port",
                    "443",
                    "--keep-connected",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 1)
            self.assertEqual(runner.calls[-1][0], [cli_path, "disconnect"])
            self.assertIn("DEAD TUNNEL", out.getvalue())

    def test_keep_connected_skips_disconnect_when_tunnel_is_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Zurich", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe(
                results=[
                    ProbeResult(reachable=True, latency_ms=80.0),
                    ProbeResult(reachable=True, latency_ms=90.0),
                ]
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--location",
                    "Zurich",
                    "--protocol",
                    "wireguard",
                    "--probe-samples",
                    "2",
                    "--keep-connected",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                [args for args, _ in runner.calls],
                [
                    [cli_path, "status"],
                    [cli_path, "connect", "Zurich", "wireguard"],
                ],
            )
            self.assertIn("85.0 ms", out.getvalue())

    def test_probe_falls_back_to_secondary_url_when_primary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Germany", stderr=""),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            probe = FakeConnectivityProbe(
                results=[
                    ProbeResult(reachable=False, error="blocked primary"),
                    ProbeResult(reachable=True, latency_ms=70.0),
                    ProbeResult(reachable=True, latency_ms=90.0),
                ]
            )
            out = io.StringIO()
            err = io.StringIO()

            exit_code = main(
                [
                    "--cli-path",
                    cli_path,
                    "--location",
                    "Germany",
                    "--protocol",
                    "wireguard",
                    "--probe-samples",
                    "2",
                ],
                runner=runner,
                probe=probe,
                stdout=out,
                stderr=err,
            )

            self.assertEqual(exit_code, 0)
            self.assertIn("80.0 ms", out.getvalue())
            # Second sample should reuse the working secondary URL first
            self.assertEqual(probe.calls[1][0], probe.calls[2][0])

    def test_keyboard_interrupt_during_probe_still_disconnects(self) -> None:
        class InterruptingProbe:
            def probe(self, url: str, *, timeout: float) -> ProbeResult:
                raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as tmpdir:
            cli_path = self._create_dummy_cli(tmpdir)
            runner = FakeCommandRunner(
                responses=[
                    CommandResult(returncode=0, stdout="Connect state: Disconnected", stderr=""),
                    CommandResult(returncode=0, stdout="Connected to Germany", stderr=""),
                    CommandResult(returncode=0, stdout="Disconnected", stderr=""),
                ]
            )
            with self.assertRaises(KeyboardInterrupt):
                main(
                    [
                        "--cli-path",
                        cli_path,
                        "--location",
                        "Germany",
                        "--protocol",
                        "wireguard",
                    ],
                    runner=runner,
                    probe=InterruptingProbe(),
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

            self.assertEqual(runner.calls[-1][0], [cli_path, "disconnect"])


if __name__ == "__main__":
    unittest.main()
