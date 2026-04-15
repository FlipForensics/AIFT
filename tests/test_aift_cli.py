"""Tests for the AIFT CLI entry point in aift_cli.py.

Covers argument parsing (help, version, list-profiles, required args, prompt
from file), and execution flow (success/failure/partial exit codes, quiet
mode, verbose mode, default output directory).
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import MagicMock, patch

from app.automation.engine import AutomationResult

# Import the CLI module functions directly.
from aift_cli import (
    EXIT_FAILURE,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    _build_parser,
    _format_duration,
    _make_progress_callback,
    _resolve_prompt,
    main,
)


def _make_result(
    success: bool = True,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> AutomationResult:
    """Build an AutomationResult for CLI testing.

    Args:
        success: Whether the result is successful.
        warnings: Optional list of warning strings.
        errors: Optional list of error strings.

    Returns:
        Populated AutomationResult.
    """
    return AutomationResult(
        success=success,
        case_id="test-case-cli",
        html_report_path=Path("/fake/report.html") if success else None,
        json_report_path=Path("/fake/report.json") if success else None,
        evidence_files=[Path("/fake/evidence.E01")],
        errors=errors or [],
        warnings=warnings or [],
        duration_seconds=10.5,
    )


class TestFormatDuration(unittest.TestCase):
    """Tests for _format_duration helper."""

    def test_seconds_only(self) -> None:
        """Duration under 60s shows seconds only."""
        self.assertEqual(_format_duration(45), "45s")

    def test_minutes_and_seconds(self) -> None:
        """Duration over 60s shows minutes and seconds."""
        self.assertEqual(_format_duration(125), "2m 05s")

    def test_zero(self) -> None:
        """Zero seconds formats correctly."""
        self.assertEqual(_format_duration(0), "0s")


class TestMakeProgressCallback(unittest.TestCase):
    """Tests for _make_progress_callback."""

    def test_quiet_returns_none(self) -> None:
        """Quiet mode returns None callback."""
        self.assertIsNone(_make_progress_callback(True))

    def test_normal_returns_callable(self) -> None:
        """Non-quiet mode returns a callable."""
        cb = _make_progress_callback(False)
        self.assertTrue(callable(cb))


class TestResolvePrompt(unittest.TestCase):
    """Tests for _resolve_prompt."""

    def test_literal_prompt(self) -> None:
        """Non-@ prompt returns as-is."""
        self.assertEqual(_resolve_prompt("Investigate this"), "Investigate this")

    def test_prompt_from_file(self) -> None:
        """@filepath reads prompt from file."""
        with TemporaryDirectory(prefix="aift-cli-") as td:
            prompt_file = Path(td) / "prompt.txt"
            prompt_file.write_text("File-based prompt", encoding="utf-8")
            result = _resolve_prompt(f"@{prompt_file}")
            self.assertEqual(result, "File-based prompt")

    def test_prompt_from_missing_file(self) -> None:
        """@nonexistent exits with error."""
        with self.assertRaises(SystemExit) as ctx:
            _resolve_prompt("@/nonexistent/prompt.txt")
        self.assertEqual(ctx.exception.code, EXIT_FAILURE)


class TestCLIArgumentParsing(unittest.TestCase):
    """Tests for CLI argument parsing."""

    def test_parser_creation(self) -> None:
        """_build_parser returns a valid ArgumentParser."""
        parser = _build_parser()
        self.assertIsNotNone(parser)

    def test_required_args_present(self) -> None:
        """Parser recognises -e and -p as required."""
        parser = _build_parser()
        args = parser.parse_args(["-e", "/path", "-p", "prompt"])
        self.assertEqual(args.evidence, "/path")
        self.assertEqual(args.prompt, "prompt")

    def test_required_args_missing(self) -> None:
        """Missing required args exits with code 2 (argparse default)."""
        parser = _build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args([])
        self.assertEqual(ctx.exception.code, 2)

    def test_optional_defaults(self) -> None:
        """Optional args have expected defaults."""
        parser = _build_parser()
        args = parser.parse_args(["-e", "/path", "-p", "prompt"])
        self.assertIsNone(args.output)
        self.assertEqual(args.profile, "recommended")
        self.assertIsNone(args.config)
        self.assertIsNone(args.case_name)
        self.assertFalse(args.skip_hashing)
        self.assertFalse(args.quiet)
        self.assertFalse(args.verbose)

    def test_all_optional_args(self) -> None:
        """All optional args can be set."""
        parser = _build_parser()
        args = parser.parse_args([
            "-e", "/path", "-p", "prompt",
            "-o", "/output",
            "--profile", "full",
            "-c", "/config.yaml",
            "--case-name", "Test Case",
            "--skip-hashing",
            "--date-start", "2026-04-01",
            "--date-end", "2026-04-15",
            "--quiet",
            "--verbose",
        ])
        self.assertEqual(args.output, "/output")
        self.assertEqual(args.profile, "full")
        self.assertEqual(args.config, "/config.yaml")
        self.assertEqual(args.case_name, "Test Case")
        self.assertTrue(args.skip_hashing)
        self.assertEqual(args.date_start, "2026-04-01")
        self.assertEqual(args.date_end, "2026-04-15")
        self.assertTrue(args.quiet)
        self.assertTrue(args.verbose)


class TestCLIVersionAndProfiles(unittest.TestCase):
    """Tests for --version and --list-profiles early exit flags."""

    @patch("aift_cli._show_version", side_effect=SystemExit(EXIT_SUCCESS))
    @patch("aift_cli.assert_supported_python_version")
    def test_version_flag(self, mock_ver: MagicMock, mock_show: MagicMock) -> None:
        """--version prints version and exits."""
        with patch("sys.argv", ["aift_cli.py", "--version"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, EXIT_SUCCESS)

    @patch("aift_cli._list_profiles", side_effect=SystemExit(EXIT_SUCCESS))
    @patch("aift_cli.assert_supported_python_version")
    def test_list_profiles_flag(
        self, mock_ver: MagicMock, mock_list: MagicMock,
    ) -> None:
        """--list-profiles prints profiles and exits."""
        with patch("sys.argv", ["aift_cli.py", "--list-profiles"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, EXIT_SUCCESS)


class TestCLIExecution(unittest.TestCase):
    """Tests for CLI execution flow.

    Patches run_automation and verify correct AutomationRequest is built.
    """

    def setUp(self) -> None:
        """Create temp dir for evidence and output stubs."""
        self.temp_dir = TemporaryDirectory(prefix="aift-cli-exec-")
        self.root = Path(self.temp_dir.name)
        self.evidence = self.root / "evidence.E01"
        self.evidence.write_bytes(b"")

    def tearDown(self) -> None:
        """Clean up temp dir."""
        self.temp_dir.cleanup()

    def _run_main(
        self,
        extra_args: list[str] | None = None,
        run_result: AutomationResult | None = None,
    ) -> int:
        """Invoke main() with patched sys.argv and run_automation.

        Args:
            extra_args: Additional CLI arguments after -e and -p.
            run_result: AutomationResult to return from the mock.

        Returns:
            Exit code from SystemExit.
        """
        args = [
            "aift_cli.py",
            "-e", str(self.evidence),
            "-p", "Test prompt",
        ] + (extra_args or [])

        result = run_result or _make_result()

        with (
            patch("sys.argv", args),
            patch("aift_cli.assert_supported_python_version"),
            patch("app.automation.engine.run_automation", return_value=result) as mock_run,
            patch("aift_cli._configure_logging"),
        ):
            try:
                main()
                return EXIT_SUCCESS  # Should not reach here normally.
            except SystemExit as e:
                return e.code

    def test_successful_run_exits_0(self) -> None:
        """Successful automation returns exit code 0."""
        code = self._run_main(run_result=_make_result(success=True))
        self.assertEqual(code, EXIT_SUCCESS)

    def test_failed_run_exits_1(self) -> None:
        """Failed automation returns exit code 1."""
        code = self._run_main(
            run_result=_make_result(success=False, errors=["Fatal error"]),
        )
        self.assertEqual(code, EXIT_FAILURE)

    def test_partial_success_exits_2(self) -> None:
        """Partial success (warnings) returns exit code 2."""
        code = self._run_main(
            run_result=_make_result(
                success=True, warnings=["minor warning"],
            ),
        )
        self.assertEqual(code, EXIT_PARTIAL)

    def test_quiet_mode_suppresses_progress(self) -> None:
        """--quiet flag results in None progress callback."""
        with (
            patch("sys.argv", [
                "aift_cli.py", "-e", str(self.evidence),
                "-p", "test", "--quiet",
            ]),
            patch("aift_cli.assert_supported_python_version"),
            patch("app.automation.engine.run_automation", return_value=_make_result()) as mock_run,
            patch("aift_cli._configure_logging"),
        ):
            try:
                main()
            except SystemExit:
                pass
            # The progress_callback kwarg should be None in quiet mode.
            call_kwargs = mock_run.call_args
            self.assertIsNone(call_kwargs.kwargs.get("progress_callback"))

    def test_default_output_is_cwd(self) -> None:
        """Without --output, reports go to current directory."""
        with (
            patch("sys.argv", [
                "aift_cli.py", "-e", str(self.evidence), "-p", "test",
            ]),
            patch("aift_cli.assert_supported_python_version"),
            patch("app.automation.engine.run_automation", return_value=_make_result()) as mock_run,
            patch("aift_cli._configure_logging"),
        ):
            try:
                main()
            except SystemExit:
                pass
            req = mock_run.call_args[0][0]
            self.assertEqual(req.output_dir, Path.cwd())

    def test_keyboard_interrupt_exits_1(self) -> None:
        """KeyboardInterrupt results in exit code 1."""
        with (
            patch("sys.argv", [
                "aift_cli.py", "-e", str(self.evidence), "-p", "test",
            ]),
            patch("aift_cli.assert_supported_python_version"),
            patch("app.automation.engine.run_automation", side_effect=KeyboardInterrupt),
            patch("aift_cli._configure_logging"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, EXIT_FAILURE)

    def test_unexpected_exception_exits_1(self) -> None:
        """Unhandled exception results in exit code 1."""
        with (
            patch("sys.argv", [
                "aift_cli.py", "-e", str(self.evidence), "-p", "test",
            ]),
            patch("aift_cli.assert_supported_python_version"),
            patch("app.automation.engine.run_automation", side_effect=RuntimeError("boom")),
            patch("aift_cli._configure_logging"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, EXIT_FAILURE)


if __name__ == "__main__":
    unittest.main()
