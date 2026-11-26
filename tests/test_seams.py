from __future__ import annotations

import sys
import unittest

from windscribe_finder.seams import HttpConnectivityProbe, SubprocessCommandRunner


class TestDefaultSeams(unittest.TestCase):
    def test_subprocess_runner_captures_output_and_exit_code(self) -> None:
        runner = SubprocessCommandRunner()
        result = runner.run([sys.executable, "-c", "print('hello')"], timeout=5.0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "hello")
        self.assertFalse(result.timed_out)

    def test_subprocess_runner_handles_timeout(self) -> None:
        runner = SubprocessCommandRunner()
        result = runner.run(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout=0.1,
        )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, -1)

    def test_module_entrypoint_help_runs_cleanly(self) -> None:
        runner = SubprocessCommandRunner()
        result = runner.run([sys.executable, "-m", "windscribe_finder", "--help"], timeout=5.0)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("--location", result.stdout)
        self.assertIn("--protocol", result.stdout)
        self.assertIn("--cli-path", result.stdout)

    def test_http_probe_returns_unreachable_result_on_invalid_endpoint(self) -> None:
        probe = HttpConnectivityProbe()
        result = probe.probe("http://127.0.0.1:1/generate_204", timeout=0.5)
        self.assertFalse(result.reachable)
        self.assertIsNone(result.latency_ms)
        self.assertTrue(result.error)


if __name__ == "__main__":
    unittest.main()
