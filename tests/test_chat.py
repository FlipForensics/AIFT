from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from app.chat import ChatManager
from app.chat.manager import _stringify as manager_stringify, VALID_ROLES
from app.chat.csv_retrieval import (
    _stringify as csv_stringify,
    build_csv_aliases,
    contains_heuristic_term,
    retrieve_csv_data,
    _read_csv_headers,
    _read_csv_rows,
    _format_csv_block,
    _match_target_paths,
    CSV_RETRIEVAL_KEYWORDS,
    CSV_ROW_LIMIT,
)


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
            # Each message is ~250 tokens -> pair is ~500 tokens.
            history = self._make_history(1, content_size=1000)
            fitted = mgr.fit_history(history, max_tokens=5)
            self.assertEqual(fitted, [])

    # ==================================================================
    # NEW TESTS: manager._stringify
    # ==================================================================

    def test_manager_stringify_with_normal_string(self) -> None:
        self.assertEqual(manager_stringify("hello"), "hello")

    def test_manager_stringify_strips_whitespace(self) -> None:
        self.assertEqual(manager_stringify("  spaced  "), "spaced")

    def test_manager_stringify_none_returns_default(self) -> None:
        self.assertEqual(manager_stringify(None), "")
        self.assertEqual(manager_stringify(None, default="N/A"), "N/A")

    def test_manager_stringify_empty_string_returns_default(self) -> None:
        self.assertEqual(manager_stringify("", default="fallback"), "fallback")
        self.assertEqual(manager_stringify("   ", default="fallback"), "fallback")

    def test_manager_stringify_non_string_value(self) -> None:
        self.assertEqual(manager_stringify(42), "42")
        self.assertEqual(manager_stringify(3.14), "3.14")

    # ==================================================================
    # NEW TESTS: ChatManager.__init__
    # ==================================================================

    def test_init_sets_case_dir_and_chat_file(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.case_dir, Path(tmp))
            self.assertEqual(mgr.chat_file, Path(tmp) / "chat_history.jsonl")

    def test_init_default_max_context_tokens(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.MAX_CONTEXT_TOKENS, 100000)

    def test_init_custom_max_context_tokens(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp, max_context_tokens=5000)
            self.assertEqual(mgr.MAX_CONTEXT_TOKENS, 5000)

    def test_init_invalid_max_context_tokens_falls_back(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp, max_context_tokens="not_a_number")
            self.assertEqual(mgr.MAX_CONTEXT_TOKENS, 100000)

    def test_init_negative_max_context_tokens_clamps_to_one(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp, max_context_tokens=-10)
            self.assertEqual(mgr.MAX_CONTEXT_TOKENS, 1)

    def test_init_zero_max_context_tokens_clamps_to_one(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp, max_context_tokens=0)
            self.assertEqual(mgr.MAX_CONTEXT_TOKENS, 1)

    # ==================================================================
    # NEW TESTS: _resolve_max_context_tokens
    # ==================================================================

    def test_resolve_max_context_tokens_with_none(self) -> None:
        self.assertEqual(ChatManager._resolve_max_context_tokens(None), 100000)

    def test_resolve_max_context_tokens_with_valid_int(self) -> None:
        self.assertEqual(ChatManager._resolve_max_context_tokens(50000), 50000)

    def test_resolve_max_context_tokens_with_string_int(self) -> None:
        self.assertEqual(ChatManager._resolve_max_context_tokens("8000"), 8000)

    def test_resolve_max_context_tokens_with_invalid_string(self) -> None:
        self.assertEqual(ChatManager._resolve_max_context_tokens("abc"), 100000)

    def test_resolve_max_context_tokens_with_negative(self) -> None:
        self.assertEqual(ChatManager._resolve_max_context_tokens(-5), 1)

    # ==================================================================
    # NEW TESTS: add_message
    # ==================================================================

    def test_add_message_user_creates_jsonl_entry(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "Hello world")
            self.assertTrue(mgr.chat_file.exists())
            lines = mgr.chat_file.read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["role"], "user")
            self.assertEqual(record["content"], "Hello world")
            self.assertIn("timestamp", record)

    def test_add_message_assistant_role(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("assistant", "I can help with that.")
            record = json.loads(mgr.chat_file.read_text(encoding="utf-8").strip())
            self.assertEqual(record["role"], "assistant")

    def test_add_message_normalizes_role_case(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("  USER  ", "test")
            record = json.loads(mgr.chat_file.read_text(encoding="utf-8").strip())
            self.assertEqual(record["role"], "user")

    def test_add_message_invalid_role_raises_value_error(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            with self.assertRaises(ValueError) as ctx:
                mgr.add_message("admin", "test")
            self.assertIn("admin", str(ctx.exception))

    def test_add_message_non_string_content_raises_type_error(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            with self.assertRaises(TypeError):
                mgr.add_message("user", 12345)

    def test_add_message_invalid_metadata_raises_type_error(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            with self.assertRaises(TypeError):
                mgr.add_message("user", "test", metadata="not_a_dict")

    def test_add_message_with_metadata_includes_it(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "test", metadata={"tokens": 42})
            record = json.loads(mgr.chat_file.read_text(encoding="utf-8").strip())
            self.assertEqual(record["metadata"], {"tokens": 42})

    def test_add_message_without_metadata_omits_key(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "test")
            record = json.loads(mgr.chat_file.read_text(encoding="utf-8").strip())
            self.assertNotIn("metadata", record)

    def test_add_message_appends_multiple(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "Q1")
            mgr.add_message("assistant", "A1")
            mgr.add_message("user", "Q2")
            lines = mgr.chat_file.read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 3)

    def test_add_message_creates_parent_dirs(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            nested = Path(tmp) / "deep" / "nested" / "case"
            mgr = ChatManager(nested)
            mgr.add_message("user", "test")
            self.assertTrue(mgr.chat_file.exists())

    # ==================================================================
    # NEW TESTS: get_history
    # ==================================================================

    def test_get_history_no_file_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.get_history(), [])

    def test_get_history_returns_all_messages(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "Q1")
            mgr.add_message("assistant", "A1")
            history = mgr.get_history()
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["role"], "user")
            self.assertEqual(history[0]["content"], "Q1")
            self.assertEqual(history[1]["role"], "assistant")

    def test_get_history_skips_malformed_json(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.chat_file.parent.mkdir(parents=True, exist_ok=True)
            content = (
                '{"role":"user","content":"valid"}\n'
                'THIS IS NOT JSON\n'
                '{"role":"assistant","content":"also valid"}\n'
            )
            mgr.chat_file.write_text(content, encoding="utf-8")
            history = mgr.get_history()
            self.assertEqual(len(history), 2)

    def test_get_history_skips_blank_lines(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.chat_file.parent.mkdir(parents=True, exist_ok=True)
            content = (
                '{"role":"user","content":"msg"}\n'
                '\n'
                '   \n'
                '{"role":"assistant","content":"reply"}\n'
            )
            mgr.chat_file.write_text(content, encoding="utf-8")
            history = mgr.get_history()
            self.assertEqual(len(history), 2)

    def test_get_history_skips_non_dict_json(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.chat_file.parent.mkdir(parents=True, exist_ok=True)
            content = (
                '{"role":"user","content":"valid"}\n'
                '"just a string"\n'
                '[1, 2, 3]\n'
            )
            mgr.chat_file.write_text(content, encoding="utf-8")
            history = mgr.get_history()
            self.assertEqual(len(history), 1)

    # ==================================================================
    # NEW TESTS: get_recent_history
    # ==================================================================

    def test_get_recent_history_returns_last_n_pairs(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            for i in range(1, 6):
                mgr.add_message("user", f"Q{i}")
                mgr.add_message("assistant", f"A{i}")
            recent = mgr.get_recent_history(max_pairs=2)
            self.assertEqual(len(recent), 4)
            self.assertEqual(recent[0]["content"], "Q4")
            self.assertEqual(recent[1]["content"], "A4")
            self.assertEqual(recent[2]["content"], "Q5")
            self.assertEqual(recent[3]["content"], "A5")

    def test_get_recent_history_zero_pairs_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "Q")
            mgr.add_message("assistant", "A")
            self.assertEqual(mgr.get_recent_history(max_pairs=0), [])

    def test_get_recent_history_negative_pairs_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.get_recent_history(max_pairs=-1), [])

    def test_get_recent_history_skips_unpaired_user_messages(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.chat_file.parent.mkdir(parents=True, exist_ok=True)
            content = (
                '{"role":"user","content":"Q1","timestamp":"t1"}\n'
                '{"role":"assistant","content":"A1","timestamp":"t2"}\n'
                '{"role":"user","content":"Q2_orphan","timestamp":"t3"}\n'
            )
            mgr.chat_file.write_text(content, encoding="utf-8")
            recent = mgr.get_recent_history(max_pairs=10)
            # Only 1 complete pair
            self.assertEqual(len(recent), 2)
            self.assertEqual(recent[0]["content"], "Q1")
            self.assertEqual(recent[1]["content"], "A1")

    def test_get_recent_history_no_file_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.get_recent_history(), [])

    def test_get_recent_history_consecutive_user_messages_takes_latest(self) -> None:
        """When two user messages appear in a row, only the second pairs with the assistant."""
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.chat_file.parent.mkdir(parents=True, exist_ok=True)
            content = (
                '{"role":"user","content":"Q1","timestamp":"t1"}\n'
                '{"role":"user","content":"Q2","timestamp":"t2"}\n'
                '{"role":"assistant","content":"A2","timestamp":"t3"}\n'
            )
            mgr.chat_file.write_text(content, encoding="utf-8")
            recent = mgr.get_recent_history(max_pairs=10)
            self.assertEqual(len(recent), 2)
            self.assertEqual(recent[0]["content"], "Q2")
            self.assertEqual(recent[1]["content"], "A2")

    # ==================================================================
    # NEW TESTS: clear
    # ==================================================================

    def test_clear_deletes_chat_file(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            mgr.add_message("user", "test")
            self.assertTrue(mgr.chat_file.exists())
            mgr.clear()
            self.assertFalse(mgr.chat_file.exists())

    def test_clear_no_file_does_nothing(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            # Should not raise
            mgr.clear()
            self.assertFalse(mgr.chat_file.exists())

    # ==================================================================
    # NEW TESTS: estimate_token_count
    # ==================================================================

    def test_estimate_token_count_empty_string(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            self.assertEqual(mgr.estimate_token_count(""), 0)

    def test_estimate_token_count_short_string(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            # 8 chars / 4 = 2 tokens
            self.assertEqual(mgr.estimate_token_count("abcdefgh"), 2)

    # ==================================================================
    # NEW TESTS: build_chat_context edge cases
    # ==================================================================

    def test_build_chat_context_none_analysis_results(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            context = mgr.build_chat_context(
                analysis_results=None,
                investigation_context="Some context",
                metadata=None,
            )
            self.assertIn("Investigation Context:", context)
            self.assertIn("No executive summary available.", context)
            self.assertIn("No per-artifact findings available.", context)
            self.assertIn("Hostname: Unknown", context)

    def test_build_chat_context_none_metadata(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            context = mgr.build_chat_context(
                analysis_results=self._make_analysis_results(),
                investigation_context="ctx",
                metadata=None,
            )
            self.assertIn("Hostname: Unknown", context)
            self.assertIn("OS: Unknown", context)
            self.assertIn("Domain: Unknown", context)

    def test_build_chat_context_empty_investigation_context(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            context = mgr.build_chat_context(
                analysis_results=self._make_analysis_results(),
                investigation_context="",
                metadata={"hostname": "H"},
            )
            self.assertIn("No investigation context provided.", context)

    def test_build_chat_context_os_key_fallback(self) -> None:
        """Metadata with 'os' key instead of 'os_version' still populates OS field."""
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            context = mgr.build_chat_context(
                analysis_results=self._make_analysis_results(),
                investigation_context="ctx",
                metadata={"hostname": "H", "os": "Windows 10"},
            )
            self.assertIn("OS: Windows 10", context)

    # ==================================================================
    # NEW TESTS: _format_per_artifact_findings
    # ==================================================================

    def test_format_findings_dict_keyed_by_artifact_name(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact": {
                    "shimcache": {"analysis": "Found evil.exe"},
                    "prefetch": {"analysis": "PSExec ran"},
                },
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("- shimcache: Found evil.exe", text)
            self.assertIn("- prefetch: PSExec ran", text)

    def test_format_findings_dict_with_plain_string_values(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact": {
                    "amcache": "Interesting binary detected",
                },
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("- amcache: Interesting binary detected", text)

    def test_format_findings_list_of_raw_strings(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact": ["Finding one", "Finding two"],
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("- Unknown Artifact: Finding one", text)
            self.assertIn("- Unknown Artifact: Finding two", text)

    def test_format_findings_empty_list(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {"per_artifact": []}
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("No per-artifact findings available.", text)

    def test_format_findings_uses_per_artifact_findings_key(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact_findings": [
                    {"artifact_name": "evtx", "analysis": "Logon events"},
                ],
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("- evtx: Logon events", text)

    def test_format_findings_no_findings_key(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {"summary": "something"}
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("No per-artifact findings available.", text)

    def test_format_findings_uses_name_key_fallback(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact": [
                    {"name": "registry", "finding": "Autorun key found"},
                ],
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("- registry: Autorun key found", text)

    def test_format_findings_uses_artifact_key_and_summary_fields(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact": [
                    {"artifact_key": "mft", "summary": "Large file created"},
                ],
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertIn("- mft: Large file created", text)

    def test_format_findings_skips_items_with_empty_analysis(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            results = {
                "per_artifact": [
                    {"artifact_name": "empty", "analysis": ""},
                    {"artifact_name": "has_data", "analysis": "real finding"},
                ],
            }
            text = mgr._format_per_artifact_findings(results)
            self.assertNotIn("- empty:", text)
            self.assertIn("- has_data: real finding", text)

    # ==================================================================
    # NEW TESTS: fit_history with unpaired messages
    # ==================================================================

    def test_fit_history_ignores_unpaired_user_message(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-") as tmp:
            mgr = ChatManager(tmp)
            history = [
                {"role": "user", "content": "Q1"},
                {"role": "assistant", "content": "A1"},
                {"role": "user", "content": "Q2_orphan"},
            ]
            fitted = mgr.fit_history(history, max_tokens=100000)
            # Only the complete pair should be returned
            self.assertEqual(len(fitted), 2)
            self.assertEqual(fitted[0]["content"], "Q1")
            self.assertEqual(fitted[1]["content"], "A1")


class CsvRetrievalStringifyTests(unittest.TestCase):
    """Tests for csv_retrieval._stringify."""

    def test_normal_string(self) -> None:
        self.assertEqual(csv_stringify("hello"), "hello")

    def test_none_returns_default(self) -> None:
        self.assertEqual(csv_stringify(None), "")
        self.assertEqual(csv_stringify(None, "N/A"), "N/A")

    def test_empty_returns_default(self) -> None:
        self.assertEqual(csv_stringify("", "fallback"), "fallback")

    def test_whitespace_only_returns_default(self) -> None:
        self.assertEqual(csv_stringify("   ", "fallback"), "fallback")

    def test_strips_whitespace(self) -> None:
        self.assertEqual(csv_stringify("  test  "), "test")

    def test_non_string_type(self) -> None:
        self.assertEqual(csv_stringify(123), "123")


class BuildCsvAliasesTests(unittest.TestCase):
    """Tests for csv_retrieval.build_csv_aliases."""

    def test_simple_csv_name(self) -> None:
        aliases = build_csv_aliases(Path("shimcache.csv"))
        self.assertIn("shimcache.csv", aliases)
        self.assertIn("shimcache", aliases)

    def test_underscore_name_generates_space_alias(self) -> None:
        aliases = build_csv_aliases(Path("net_connections.csv"))
        self.assertIn("net connections", aliases)
        self.assertIn("net_connections", aliases)
        # Leading segment before first underscore
        self.assertIn("net", aliases)

    def test_part_suffix_removed(self) -> None:
        aliases = build_csv_aliases(Path("evtx_part2.csv"))
        self.assertIn("evtx_part2", aliases)
        self.assertIn("evtx", aliases)  # base after removing _part2

    def test_complex_name_with_part_suffix(self) -> None:
        aliases = build_csv_aliases(Path("windows_event_log_part3.csv"))
        self.assertIn("windows_event_log", aliases)
        self.assertIn("windows event log", aliases)
        self.assertIn("windows", aliases)

    def test_no_empty_aliases(self) -> None:
        aliases = build_csv_aliases(Path("test.csv"))
        for alias in aliases:
            self.assertTrue(len(alias) > 0)


class ContainsHeuristicTermTests(unittest.TestCase):
    """Tests for csv_retrieval.contains_heuristic_term."""

    def test_exact_match(self) -> None:
        self.assertTrue(contains_heuristic_term("show me the shimcache data", "shimcache"))

    def test_term_at_start(self) -> None:
        self.assertTrue(contains_heuristic_term("shimcache has entries", "shimcache"))

    def test_term_at_end(self) -> None:
        self.assertTrue(contains_heuristic_term("show me shimcache", "shimcache"))

    def test_no_match(self) -> None:
        self.assertFalse(contains_heuristic_term("nothing here", "shimcache"))

    def test_short_term_rejected(self) -> None:
        self.assertFalse(contains_heuristic_term("ab is short", "ab"))
        self.assertFalse(contains_heuristic_term("x marks the spot", "x"))

    def test_exactly_three_chars(self) -> None:
        self.assertTrue(contains_heuristic_term("the mft is big", "mft"))

    def test_substring_no_boundary_match(self) -> None:
        # "net" should not match inside "internet" since word boundary check
        self.assertFalse(contains_heuristic_term("check internet logs", "net"))

    def test_term_with_surrounding_punctuation(self) -> None:
        self.assertTrue(contains_heuristic_term("check shimcache, please", "shimcache"))

    def test_term_case_normalized(self) -> None:
        self.assertTrue(contains_heuristic_term("show shimcache data", "SHIMCACHE"))


class ReadCsvHeadersTests(unittest.TestCase):
    """Tests for csv_retrieval._read_csv_headers."""

    @staticmethod
    def _write_csv(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def test_reads_valid_headers(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            self._write_csv(csv_path, "name,path,hash\nval1,val2,val3\n")
            headers = _read_csv_headers(csv_path)
            self.assertEqual(headers, ["name", "path", "hash"])

    def test_empty_file_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "empty.csv"
            self._write_csv(csv_path, "")
            headers = _read_csv_headers(csv_path)
            self.assertEqual(headers, [])

    def test_nonexistent_file_returns_empty(self) -> None:
        headers = _read_csv_headers(Path("/nonexistent/path/file.csv"))
        self.assertEqual(headers, [])

    def test_filters_empty_header_values(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            self._write_csv(csv_path, "name,,path,\nval1,,val2,\n")
            headers = _read_csv_headers(csv_path)
            self.assertEqual(headers, ["name", "path"])


class ReadCsvRowsTests(unittest.TestCase):
    """Tests for csv_retrieval._read_csv_rows."""

    @staticmethod
    def _write_csv(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def test_reads_rows_within_limit(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            self._write_csv(csv_path, "name,value\nalpha,1\nbeta,2\ngamma,3\n")
            headers, rows, total = _read_csv_rows(csv_path, limit=10)
            self.assertEqual(headers, ["name", "value"])
            self.assertEqual(len(rows), 3)
            self.assertEqual(total, 3)
            self.assertEqual(rows[0]["name"], "alpha")

    def test_limit_restricts_returned_rows(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            lines = "idx\n" + "\n".join(str(i) for i in range(50))
            self._write_csv(csv_path, lines + "\n")
            headers, rows, total = _read_csv_rows(csv_path, limit=5)
            self.assertEqual(len(rows), 5)
            self.assertEqual(total, 50)

    def test_zero_limit_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            self._write_csv(csv_path, "a,b\n1,2\n")
            headers, rows, total = _read_csv_rows(csv_path, limit=0)
            self.assertEqual(headers, [])
            self.assertEqual(rows, [])
            self.assertEqual(total, 0)

    def test_negative_limit_returns_empty(self) -> None:
        headers, rows, total = _read_csv_rows(Path("dummy.csv"), limit=-1)
        self.assertEqual((headers, rows, total), ([], [], 0))

    def test_long_values_truncated(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            long_val = "x" * 300
            self._write_csv(csv_path, f"col\n{long_val}\n")
            headers, rows, total = _read_csv_rows(csv_path, limit=10)
            self.assertEqual(len(rows[0]["col"]), 240)
            self.assertTrue(rows[0]["col"].endswith("..."))

    def test_whitespace_collapsed(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "test.csv"
            self._write_csv(csv_path, "col\nhello   world   test\n")
            headers, rows, total = _read_csv_rows(csv_path, limit=10)
            self.assertEqual(rows[0]["col"], "hello world test")

    def test_nonexistent_file_returns_empty(self) -> None:
        headers, rows, total = _read_csv_rows(Path("/no/such/file.csv"), limit=10)
        self.assertEqual((headers, rows, total), ([], [], 0))


class FormatCsvBlockTests(unittest.TestCase):
    """Tests for csv_retrieval._format_csv_block."""

    def test_basic_format(self) -> None:
        block = _format_csv_block(
            "test.csv",
            ["name", "value"],
            [{"name": "alpha", "value": "1"}],
            1,
        )
        self.assertIn("Artifact: test.csv", block)
        self.assertIn("Total rows: 1", block)
        self.assertIn("Columns: name, value", block)
        self.assertIn("1. name=alpha | value=1", block)

    def test_truncation_note_when_showing_fewer(self) -> None:
        block = _format_csv_block(
            "test.csv",
            ["col"],
            [{"col": "a"}, {"col": "b"}],
            100,
        )
        self.assertIn("showing first 2", block)

    def test_no_truncation_note_when_all_shown(self) -> None:
        block = _format_csv_block(
            "test.csv",
            ["col"],
            [{"col": "a"}],
            1,
        )
        self.assertNotIn("showing first", block)

    def test_no_rows_shows_none(self) -> None:
        block = _format_csv_block("test.csv", ["col"], [], 0)
        self.assertIn("Rows: none", block)

    def test_no_headers_omits_columns_line(self) -> None:
        block = _format_csv_block("test.csv", [], [], 0)
        self.assertNotIn("Columns:", block)

    def test_multiple_rows_numbered(self) -> None:
        rows = [{"c": f"v{i}"} for i in range(3)]
        block = _format_csv_block("test.csv", ["c"], rows, 3)
        self.assertIn("1. c=v0", block)
        self.assertIn("2. c=v1", block)
        self.assertIn("3. c=v2", block)


class MatchTargetPathsTests(unittest.TestCase):
    """Tests for csv_retrieval._match_target_paths."""

    @staticmethod
    def _write_csv(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def test_artifact_name_match(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            p1 = Path(tmp) / "shimcache.csv"
            p2 = Path(tmp) / "prefetch.csv"
            self._write_csv(p1, "col\nval\n")
            self._write_csv(p2, "col\nval\n")
            result = _match_target_paths([p1, p2], "show me shimcache data", False)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].name, "shimcache.csv")

    def test_column_header_match(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            p1 = Path(tmp) / "connections.csv"
            self._write_csv(p1, "source_ip,destination_ip\n10.0.0.1,10.0.0.2\n")
            result = _match_target_paths([p1], "what about the destination_ip", False)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 1)

    def test_keyword_fallback_small_collection(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            p1 = Path(tmp) / "data1.csv"
            p2 = Path(tmp) / "data2.csv"
            self._write_csv(p1, "a\n1\n")
            self._write_csv(p2, "b\n2\n")
            # keyword_detected=True and only 2 CSVs (<=3) => return all
            result = _match_target_paths([p1, p2], "xyz unrelated question", True)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 2)

    def test_no_match_returns_none(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            p1 = Path(tmp) / "data1.csv"
            self._write_csv(p1, "col\nval\n")
            # No artifact match, no column match, keyword_detected=False
            result = _match_target_paths([p1], "unrelated question", False)
            self.assertIsNone(result)

    def test_keyword_fallback_skipped_for_large_collection(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            paths = []
            for i in range(5):
                p = Path(tmp) / f"data{i}.csv"
                self._write_csv(p, "x\ny\n")
                paths.append(p)
            result = _match_target_paths(paths, "unrelated", True)
            self.assertIsNone(result)


class RetrieveCsvDataEdgeCasesTests(unittest.TestCase):
    """Tests for csv_retrieval.retrieve_csv_data edge cases."""

    def test_empty_question_returns_not_retrieved(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            result = retrieve_csv_data("", tmp)
            self.assertEqual(result, {"retrieved": False})

    def test_none_question_returns_not_retrieved(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            result = retrieve_csv_data(None, tmp)
            self.assertEqual(result, {"retrieved": False})

    def test_nonexistent_dir_returns_not_retrieved(self) -> None:
        result = retrieve_csv_data("show me data", "/no/such/directory")
        self.assertEqual(result, {"retrieved": False})

    def test_empty_dir_returns_not_retrieved(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            result = retrieve_csv_data("show me csv data", tmp)
            self.assertEqual(result, {"retrieved": False})

    def test_matched_csv_with_no_readable_rows(self) -> None:
        """When CSV matches by name but has only a header and no data rows."""
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "shimcache.csv"
            csv_path.write_text("path,sha1\n", encoding="utf-8")
            result = retrieve_csv_data("show me shimcache rows", tmp)
            self.assertTrue(result["retrieved"])
            self.assertIn("shimcache.csv", result["artifacts"])
            # Should show "No readable rows" or similar since no data rows
            # The function returns the artifact but with "Rows: none" in the block
            self.assertIn("Rows: none", result["data"])

    def test_keyword_fallback_returns_all_small_csv_set(self) -> None:
        """When keywords detected and <=3 CSVs, returns all."""
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            p1 = Path(tmp) / "data_alpha.csv"
            p1.write_text("col\nval\n", encoding="utf-8")
            # "list" is a keyword, "data_alpha" doesn't match "something"
            # but with <=3 csvs and keyword, should fall back
            result = retrieve_csv_data("list something unrelated", tmp)
            self.assertTrue(result["retrieved"])

    def test_custom_row_limit(self) -> None:
        with TemporaryDirectory(prefix="aift-csv-") as tmp:
            csv_path = Path(tmp) / "shimcache.csv"
            lines = "path\n" + "\n".join(f"file{i}.exe" for i in range(20))
            csv_path.write_text(lines + "\n", encoding="utf-8")
            result = retrieve_csv_data("show me shimcache rows", tmp, row_limit=5)
            self.assertTrue(result["retrieved"])
            self.assertIn("showing first 5", result["data"])
            self.assertIn("Total rows: 20", result["data"])


class CsvRetrievalKeywordsTests(unittest.TestCase):
    """Tests for module-level constants in csv_retrieval."""

    def test_keywords_is_tuple(self) -> None:
        self.assertIsInstance(CSV_RETRIEVAL_KEYWORDS, tuple)

    def test_row_limit_is_500(self) -> None:
        self.assertEqual(CSV_ROW_LIMIT, 500)

    def test_all_keywords_lowercase(self) -> None:
        for kw in CSV_RETRIEVAL_KEYWORDS:
            self.assertEqual(kw, kw.lower())


class ValidRolesTests(unittest.TestCase):
    """Tests for manager module-level constants."""

    def test_valid_roles_contains_user_and_assistant(self) -> None:
        self.assertIn("user", VALID_ROLES)
        self.assertIn("assistant", VALID_ROLES)
        self.assertEqual(len(VALID_ROLES), 2)


if __name__ == "__main__":
    unittest.main()
