#!/usr/bin/env python3
"""AIFT CLI — Command-line interface for automated forensic triage.

Provides a standalone command-line tool that runs the full AIFT forensic
analysis pipeline without starting the Flask web server. Evidence files
or folders are processed, artifacts are parsed, AI analysis is performed,
and both HTML and JSON reports are generated.

Usage:
    python aift_cli.py -e /path/to/evidence -p "Investigate suspicious activity"
    python aift_cli.py -e /evidence/folder -p @prompt.txt -o /output --profile recommended

Attributes:
    EXIT_SUCCESS: Exit code for successful completion (0).
    EXIT_FAILURE: Exit code for fatal errors (1).
    EXIT_PARTIAL: Exit code for partial success with warnings (2).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from runtime_compat import UnsupportedPythonVersionError, assert_supported_python_version

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_PARTIAL = 2

# Project root: aift_cli.py lives at the repository root.
_PROJECT_ROOT = Path(__file__).resolve().parent


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the AIFT CLI.

    Returns:
        Configured ``argparse.ArgumentParser`` instance.
    """
    parser = argparse.ArgumentParser(
        prog="aift_cli.py",
        description="AIFT - AI Forensic Triage (CLI Mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "-e", "--evidence",
        required=True,
        metavar="EVIDENCE",
        help=(
            "Path to evidence file or folder. If a folder is given, all "
            "supported evidence files within it will be discovered and processed."
        ),
    )
    required.add_argument(
        "-p", "--prompt",
        required=True,
        metavar="PROMPT",
        help=(
            "Investigation context / prompt for AI analysis. Can be a string "
            "or a path to a text file (prefix with @, e.g., @prompt.txt)."
        ),
    )

    optional = parser.add_argument_group("optional arguments")
    optional.add_argument(
        "-o", "--output",
        metavar="OUTPUT",
        default=None,
        help="Output directory for reports. Defaults to current working directory.",
    )
    optional.add_argument(
        "--profile",
        metavar="PROFILE",
        default="recommended",
        help=(
            'Artifact profile name. Defaults to "recommended". '
            "Use --list-profiles to see available profiles."
        ),
    )
    optional.add_argument(
        "-c", "--config",
        metavar="CONFIG",
        default=None,
        help=(
            "Path to config.yaml. Defaults to the config.yaml "
            "in the AIFT installation directory."
        ),
    )
    optional.add_argument(
        "--case-name",
        metavar="NAME",
        default=None,
        help="Human-readable case name. Auto-generated if not provided.",
    )
    optional.add_argument(
        "--skip-hashing",
        action="store_true",
        default=False,
        help="Skip SHA-256/MD5 hash computation on evidence.",
    )
    optional.add_argument(
        "--date-start",
        metavar="DATE",
        default=None,
        help="Start date for analysis filtering (YYYY-MM-DD).",
    )
    optional.add_argument(
        "--date-end",
        metavar="DATE",
        default=None,
        help="End date for analysis filtering (YYYY-MM-DD).",
    )
    optional.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress progress output. Only print final result.",
    )
    optional.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug-level logging.",
    )
    optional.add_argument(
        "--list-profiles",
        action="store_true",
        default=False,
        help="List available artifact profiles and exit.",
    )
    optional.add_argument(
        "--version",
        action="store_true",
        default=False,
        help="Show version and exit.",
    )

    return parser


def _resolve_prompt(raw_prompt: str) -> str:
    """Resolve the prompt argument, loading from file if prefixed with ``@``.

    Args:
        raw_prompt: The raw ``--prompt`` value from the CLI.

    Returns:
        The investigation prompt string.

    Raises:
        SystemExit: If the prompt file does not exist or cannot be read.
    """
    if raw_prompt.startswith("@"):
        file_path = Path(raw_prompt[1:]).expanduser().resolve()
        if not file_path.is_file():
            print(f"ERROR: Prompt file not found: {file_path}", file=sys.stderr)
            raise SystemExit(EXIT_FAILURE)
        try:
            return file_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            print(f"ERROR: Failed to read prompt file: {exc}", file=sys.stderr)
            raise SystemExit(EXIT_FAILURE) from None
    return raw_prompt


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted string like ``"2m 05s"`` or ``"45s"``.
    """
    minutes = int(seconds) // 60
    secs = int(seconds) % 60
    if minutes > 0:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _make_progress_callback(quiet: bool) -> Any:
    """Create a progress callback function for the automation engine.

    Args:
        quiet: If True, return None (suppress progress output).

    Returns:
        A callback ``(phase, message, percentage) -> None`` or None.
    """
    if quiet:
        return None

    phase_labels = {
        "discovery": "DISCOVERY",
        "hashing": "HASHING  ",
        "parsing": "PARSING  ",
        "analysis": "ANALYSIS ",
        "reporting": "REPORTING",
    }

    def _callback(phase: str, message: str, percentage: float) -> None:
        """Print a formatted progress line to stdout.

        Args:
            phase: Pipeline phase name.
            message: Human-readable status message.
            percentage: Progress within the phase (0.0--100.0).
        """
        label = phase_labels.get(phase, phase.upper().ljust(9))
        print(f"[{label}] {message}")

    return _callback


def _print_summary(result: Any) -> None:
    """Print the final summary block after automation completes.

    Args:
        result: An ``AutomationResult`` instance from the automation engine.
    """
    separator = "=" * 60
    print()
    print(separator)
    if result.success:
        print("AIFT Automation Complete")
    else:
        print("AIFT Automation Complete (with errors)")
    print(separator)
    print(f"  Case ID:      {result.case_id or 'N/A'}")
    print(f"  Evidence:     {len(result.evidence_files)} file(s) processed")
    print(f"  Duration:     {_format_duration(result.duration_seconds)}")
    print()

    if result.html_report_path or result.json_report_path:
        print("  Reports:")
        if result.html_report_path:
            print(f"    HTML: {result.html_report_path}")
        if result.json_report_path:
            print(f"    JSON: {result.json_report_path}")
        print()

    if result.errors:
        print(f"  Errors: {len(result.errors)}")
        for err in result.errors:
            print(f"    - {err}")
        print()

    if result.warnings:
        print(f"  Warnings: {len(result.warnings)}")
        for warn in result.warnings:
            print(f"    - {warn}")
        print()

    print(separator)


def _list_profiles() -> None:
    """Load and print all available artifact profiles, then exit.

    Raises:
        SystemExit: Always exits with code 0 after printing.
    """
    from app.routes.artifacts import load_profiles_from_directory

    profiles_root = _PROJECT_ROOT / "profile"
    profiles = load_profiles_from_directory(profiles_root)

    if not profiles:
        print("No artifact profiles found.")
        raise SystemExit(EXIT_SUCCESS)

    print("Available artifact profiles:\n")
    for profile in profiles:
        name = profile.get("name", "unknown")
        builtin = profile.get("builtin", False)
        artifact_count = len(profile.get("artifact_options", []))
        tag = " (built-in)" if builtin else ""
        print(f"  {name}{tag} — {artifact_count} artifacts")

    print()
    raise SystemExit(EXIT_SUCCESS)


def _show_version() -> None:
    """Print the AIFT version and exit.

    Raises:
        SystemExit: Always exits with code 0 after printing.
    """
    from app.version import TOOL_VERSION

    print(f"AIFT v{TOOL_VERSION}")
    raise SystemExit(EXIT_SUCCESS)


def _configure_logging(verbose: bool) -> None:
    """Configure Python logging for the CLI session.

    Args:
        verbose: If True, set ``app`` loggers to DEBUG. Otherwise, WARNING.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("app").setLevel(level)


def main() -> None:
    """Parse arguments and run the AIFT automation pipeline.

    This is the CLI entry point. It validates the Python version, parses
    command-line arguments, resolves the investigation prompt, builds an
    ``AutomationRequest``, calls ``run_automation()``, and prints the
    summary.

    Raises:
        SystemExit: With exit code 0 (success), 1 (failure), or
            2 (partial success with warnings).
    """
    assert_supported_python_version()

    # Check for early-exit flags before full argument parsing, since
    # --version and --list-profiles should work without -e and -p.
    if "--version" in sys.argv[1:]:
        _show_version()
    if "--list-profiles" in sys.argv[1:]:
        _configure_logging("--verbose" in sys.argv[1:])
        _list_profiles()

    parser = _build_parser()
    args = parser.parse_args()

    _configure_logging(args.verbose)

    # Resolve prompt (may be a file reference).
    prompt = _resolve_prompt(args.prompt)
    if not prompt:
        print("ERROR: Investigation prompt must not be empty.", file=sys.stderr)
        raise SystemExit(EXIT_FAILURE)

    # Build date range if specified.
    date_range: tuple[str, str] | None = None
    if args.date_start and args.date_end:
        date_range = (args.date_start, args.date_end)
    elif args.date_start or args.date_end:
        print(
            "ERROR: Both --date-start and --date-end must be provided together.",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_FAILURE)

    # Resolve output directory.
    output_dir = Path(args.output).resolve() if args.output else Path.cwd()

    # Lazy-import the automation engine to avoid loading Flask.
    from app.automation.engine import AutomationRequest, run_automation

    request = AutomationRequest(
        evidence_path=args.evidence,
        prompt=prompt,
        output_dir=output_dir,
        profile_name=args.profile,
        config_path=args.config,
        case_name=args.case_name,
        skip_hashing=args.skip_hashing,
        date_range=date_range,
    )

    progress_callback = _make_progress_callback(args.quiet)

    try:
        result = run_automation(request, progress_callback=progress_callback)
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        raise SystemExit(EXIT_FAILURE) from None
    except Exception as exc:
        logging.getLogger(__name__).debug("Unhandled exception", exc_info=True)
        print(f"ERROR: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        raise SystemExit(EXIT_FAILURE) from None

    _print_summary(result)

    if not result.success:
        raise SystemExit(EXIT_FAILURE)
    if result.warnings:
        raise SystemExit(EXIT_PARTIAL)
    raise SystemExit(EXIT_SUCCESS)


if __name__ == "__main__":
    try:
        main()
    except UnsupportedPythonVersionError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(EXIT_FAILURE) from None
