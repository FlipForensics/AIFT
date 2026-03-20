"""Tests for the parse-only workflow guard in the frontend JavaScript.

Verifies that when no AI-enabled artifacts are selected, the UI does not
auto-advance into the analysis step after parsing completes, and that
navigation to the analysis step is blocked with clear messaging.

These tests inspect the JavaScript source files to confirm the guard logic
is present.  A companion HTML file (``static/tests/test_parse_only_flow.html``)
provides interactive browser-based verification of the same invariants.

Attributes:
    STATIC_DIR: Resolved path to the ``static/`` directory.
"""

from __future__ import annotations

import unittest
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


class TestParseCompletedGuard(unittest.TestCase):
    """Verify parsing.js does not auto-advance to analysis without AI artifacts."""

    def setUp(self) -> None:
        """Load parsing.js source."""
        self.source = (STATIC_DIR / "js" / "parsing.js").read_text(encoding="utf-8")

    def test_parse_completed_checks_selected_ai(self) -> None:
        """parse_completed handler must check st.selectedAi.length before showStep(4)."""
        self.assertIn(
            "st.selectedAi.length > 0",
            self.source,
            "parse_completed must guard showStep(4) behind st.selectedAi.length > 0",
        )

    def test_parse_completed_shows_parse_only_message(self) -> None:
        """parse_completed must show a clear message when no AI artifacts are selected."""
        self.assertIn(
            "Parsing complete",
            self.source,
            "parse_completed must display a 'Parsing complete' message for parse-only flows",
        )

    def test_show_step_4_is_conditional(self) -> None:
        """showStep(4) must only appear after the selectedAi guard, not unconditionally."""
        lines = self.source.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "showStep(4)" in stripped:
                # The line (or the line before it) must reference selectedAi
                context = "\n".join(lines[max(0, i - 2) : i + 1])
                self.assertIn(
                    "selectedAi",
                    context,
                    f"showStep(4) at line {i + 1} is not guarded by selectedAi check",
                )


class TestNavBlockReason(unittest.TestCase):
    """Verify app.js blocks navigation to step 4 when no AI artifacts exist."""

    def setUp(self) -> None:
        """Load app.js source."""
        self.source = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

    def test_step4_blocks_without_ai_artifacts(self) -> None:
        """navBlockReason for step 4 must check selectedAi.length."""
        self.assertIn(
            "selectedAi.length === 0",
            self.source,
            "navBlockReason must block step 4 when selectedAi is empty",
        )

    def test_step4_block_message_mentions_parse_and_ai(self) -> None:
        """The block message must tell the user to re-parse with AI-enabled artifacts."""
        self.assertIn(
            "Parse and use in AI",
            self.source,
            "navBlockReason step-4 message must reference 'Parse and use in AI'",
        )


class TestAnalysisGuard(unittest.TestCase):
    """Verify analysis.js still guards against empty selectedAi at submit time."""

    def setUp(self) -> None:
        """Load analysis.js source."""
        self.source = (STATIC_DIR / "js" / "analysis.js").read_text(encoding="utf-8")

    def test_submit_analysis_checks_selected_ai(self) -> None:
        """submitAnalysis must reject when st.selectedAi is empty."""
        self.assertIn(
            "selectedAi.length",
            self.source,
            "submitAnalysis must check st.selectedAi.length",
        )


if __name__ == "__main__":
    unittest.main()
