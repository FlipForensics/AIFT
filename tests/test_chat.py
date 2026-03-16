from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.chat import ChatManager


class ChatManagerTests(unittest.TestCase):
    @staticmethod
    def _write_csv(path: Path, header: str, rows: list[str]) -> None:
        lines = [header, *rows]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_build_chat_context_includes_expected_sections(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-context-test-") as temp_dir:
            manager = ChatManager(temp_dir)
            context = manager.build_chat_context(
                analysis_results={
                    "summary": "Execution artifacts indicate suspicious lateral movement.",
                    "per_artifact": [
                        {
                            "artifact_name": "Shimcache",
                            "analysis": "Cmd.exe spawned from an unusual temp path.",
                        },
                        {
                            "artifact_name": "Prefetch",
                            "analysis": "PSExec executed multiple times in close succession.",
                        },
                    ],
                },
                investigation_context="Investigate unauthorized admin activity on host WIN-IR-01.",
                metadata={"hostname": "WIN-IR-01", "os_version": "Windows 11", "domain": "CORP"},
            )

        self.assertIn("Investigation Context:", context)
        self.assertIn("System Under Analysis:", context)
        self.assertIn("Executive Summary:", context)
        self.assertIn("Per-Artifact Findings:", context)
        self.assertIn("Hostname: WIN-IR-01", context)
        self.assertIn("OS: Windows 11", context)
        self.assertIn("Domain: CORP", context)
        self.assertIn("Shimcache", context)
        self.assertIn("Prefetch", context)

    def test_retrieve_csv_data_artifact_match_retrieves_target_csv(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-retrieval-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "shimcache.csv",
                "path,sha1",
                [
                    r"C:\Temp\evil.exe,abc123",
                    r"C:\Windows\System32\cmd.exe,def456",
                ],
            )
            self._write_csv(
                parsed_dir / "prefetch.csv",
                "exe,last_run",
                [
                    "cmd.exe,2026-02-20T12:30:00Z",
                ],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="Check the shimcache CSV and show me rows with temp paths.",
                parsed_dir=parsed_dir,
            )

        self.assertTrue(result["retrieved"])
        self.assertEqual(result["artifacts"], ["shimcache.csv"])
        self.assertIn("Artifact: shimcache.csv", result["data"])
        self.assertIn(r"C:\Temp\evil.exe", result["data"])

    def test_retrieve_csv_data_column_match_retrieves_data(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-column-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "net_connections.csv",
                "source_ip,destination_ip,port",
                [
                    "10.0.0.10,10.0.0.55,445",
                    "10.0.0.10,185.199.111.153,443",
                ],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="List records where destination_ip is external.",
                parsed_dir=parsed_dir,
            )

        self.assertTrue(result["retrieved"])
        self.assertEqual(result["artifacts"], ["net_connections.csv"])
        self.assertIn("destination_ip", result["data"])

    def test_retrieve_csv_data_returns_false_when_not_data_request(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-nodata-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "shimcache.csv",
                "path,sha1",
                [r"C:\Temp\evil.exe,abc123"],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="What does this investigation suggest overall?",
                parsed_dir=parsed_dir,
            )

        self.assertEqual(result, {"retrieved": False})

    def test_retrieve_csv_data_shows_total_row_count_when_truncated(self) -> None:
        """Verify that large CSVs include a 'Total rows' summary."""
        with TemporaryDirectory(prefix="aift-chat-rowcount-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            # Write a CSV with more rows than _CSV_ROW_LIMIT (500).
            rows = [f"evil_{i}.exe,hash_{i}" for i in range(600)]
            self._write_csv(parsed_dir / "shimcache.csv", "path,sha1", rows)

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="Show me shimcache rows",
                parsed_dir=parsed_dir,
            )

        self.assertTrue(result["retrieved"])
        self.assertIn("Total rows: 600", result["data"])
        self.assertIn("showing first 500", result["data"])

    def test_retrieve_csv_data_no_truncation_note_for_small_csv(self) -> None:
        """Verify small CSVs show total rows without a truncation note."""
        with TemporaryDirectory(prefix="aift-chat-small-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "shimcache.csv",
                "path,sha1",
                [r"C:\Temp\evil.exe,abc123"],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="Show me shimcache rows",
                parsed_dir=parsed_dir,
            )

        self.assertTrue(result["retrieved"])
        self.assertIn("Total rows: 1", result["data"])
        self.assertNotIn("showing first", result["data"])

    def test_estimate_token_count_and_max_context_tokens(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-token-test-") as temp_dir:
            manager = ChatManager(temp_dir)
            configured_manager = ChatManager(temp_dir, max_context_tokens=2048)

            self.assertEqual(manager.MAX_CONTEXT_TOKENS, 100000)
            self.assertEqual(configured_manager.MAX_CONTEXT_TOKENS, 2048)
            self.assertEqual(manager.estimate_token_count("abcd" * 10), 10)

    # ------------------------------------------------------------------
    # Context window management
    # ------------------------------------------------------------------

    def _make_analysis_results(self, finding_text: str = "Short.") -> dict:
        return {
            "summary": "Executive summary.",
            "per_artifact": [
                {"artifact_name": "shimcache", "analysis": finding_text},
                {"artifact_name": "prefetch", "analysis": finding_text},
            ],
        }

    def test_context_needs_compression_returns_false_when_within_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            context = mgr.build_chat_context(
                analysis_results=self._make_analysis_results(),
                investigation_context="Test context.",
                metadata={"hostname": "HOST"},
            )
            # Budget is very large — no compression needed.
            self.assertFalse(mgr.context_needs_compression(context, 100000))

    def test_context_needs_compression_returns_true_when_over_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            # Create a large context by using verbose findings.
            long_text = "Suspicious activity detected. " * 200
            context = mgr.build_chat_context(
                analysis_results=self._make_analysis_results(long_text),
                investigation_context="Test context.",
                metadata={"hostname": "HOST"},
            )
            # Budget is tiny — compression needed.
            self.assertTrue(mgr.context_needs_compression(context, 500))

    def test_context_needs_compression_handles_zero_and_negative_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertFalse(mgr.context_needs_compression("any text", 0))
            self.assertFalse(mgr.context_needs_compression("any text", -1))

    def test_rebuild_context_with_compressed_findings(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            rebuilt = mgr.rebuild_context_with_compressed_findings(
                analysis_results=self._make_analysis_results(),
                investigation_context="Test context.",
                metadata={"hostname": "HOST", "os_version": "Win11", "domain": "CORP"},
                compressed_findings="- shimcache: Compressed.\n- prefetch: Compressed.",
            )
            self.assertIn("Per-Artifact Findings (compressed):", rebuilt)
            self.assertIn("- shimcache: Compressed.", rebuilt)
            self.assertIn("- prefetch: Compressed.", rebuilt)
            # The always-included sections are still present.
            self.assertIn("Investigation Context:", rebuilt)
            self.assertIn("Executive Summary:", rebuilt)
            self.assertIn("Hostname: HOST", rebuilt)

    def test_rebuild_context_is_smaller_than_original(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            long_text = "Suspicious lateral movement via psexec. " * 100
            results = self._make_analysis_results(long_text)
            meta = {"hostname": "H", "os_version": "W", "domain": "D"}

            original = mgr.build_chat_context(
                analysis_results=results,
                investigation_context="ctx",
                metadata=meta,
            )
            rebuilt = mgr.rebuild_context_with_compressed_findings(
                analysis_results=results,
                investigation_context="ctx",
                metadata=meta,
                compressed_findings="- shimcache: Compressed.\n- prefetch: Compressed.",
            )
            self.assertLess(len(rebuilt), len(original))

    # ------------------------------------------------------------------
    # fit_history
    # ------------------------------------------------------------------

    def _make_history(self, pairs: int, content_size: int = 20) -> list[dict]:
        """Create *pairs* user/assistant message pairs."""
        history: list[dict] = []
        for i in range(1, pairs + 1):
            history.append({"role": "user", "content": f"Q{i} " + "x" * content_size})
            history.append({"role": "assistant", "content": f"A{i} " + "y" * content_size})
        return history

    def test_fit_history_returns_all_when_within_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            history = self._make_history(3, content_size=10)
            fitted = mgr.fit_history(history, max_tokens=100000)
            self.assertEqual(len(fitted), 6)

    def test_fit_history_drops_oldest_pairs_first(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            history = self._make_history(5, content_size=100)
            # Budget only fits ~1-2 pairs.
            fitted = mgr.fit_history(history, max_tokens=60)
            self.assertGreater(len(fitted), 0)
            self.assertLess(len(fitted), len(history))
            # The remaining messages should be from the most recent pairs.
            roles = [m["role"] for m in fitted]
            self.assertEqual(roles, ["user", "assistant"] * (len(fitted) // 2))
            # Last pair should be the newest.
            self.assertIn("Q5", fitted[-2]["content"])
            self.assertIn("A5", fitted[-1]["content"])

    def test_fit_history_returns_empty_on_zero_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.fit_history(self._make_history(3), max_tokens=0), [])

    def test_fit_history_returns_empty_on_negative_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.fit_history(self._make_history(3), max_tokens=-10), [])

    def test_fit_history_returns_empty_for_empty_input(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.fit_history([], max_tokens=10000), [])

    def test_fit_history_drops_all_when_single_pair_exceeds_budget(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            # Each message is ~250 tokens → pair is ~500 tokens.
            history = self._make_history(1, content_size=1000)
            fitted = mgr.fit_history(history, max_tokens=5)
            self.assertEqual(fitted, [])


if __name__ == "__main__":
    unittest.main()
