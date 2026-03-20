from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import app.routes.tasks as routes_tasks


class RenderChatMessagesForProviderTests(unittest.TestCase):
    def test_renders_context_history_and_latest_question(self) -> None:
        messages = [
            {"role": "system", "content": "ignored system prompt"},
            {"role": "user", "content": "  Case context  "},
            {"role": "assistant", "content": "Earlier assistant reply"},
            {"role": "user", "content": "Follow-up clarification"},
            {"role": "tool", "content": "Tool output"},
            {"role": "user", "content": "Latest question"},
            {"role": "assistant", "content": "   "},
        ]

        rendered = routes_tasks._render_chat_messages_for_provider(messages)

        self.assertEqual(
            rendered,
            "\n\n".join(
                [
                    "Context Block:\nCase context",
                    "Assistant:\nEarlier assistant reply",
                    "User:\nFollow-up clarification",
                    "Tool:\nTool output",
                    "New User Question:\nLatest question",
                ]
            ),
        )

    def test_returns_empty_string_when_no_non_system_content_exists(self) -> None:
        rendered = routes_tasks._render_chat_messages_for_provider(
            [
                {"role": "system", "content": "ignored"},
                {"role": "user", "content": "   "},
                {"role": "assistant", "content": ""},
            ]
        )

        self.assertEqual(rendered, "")


class ResolveChatMaxTokensTests(unittest.TestCase):
    def test_returns_positive_integer(self) -> None:
        result = routes_tasks._resolve_chat_max_tokens({"analysis": {"ai_max_tokens": "4096"}})
        self.assertEqual(result, 4096)

    def test_rejects_missing_analysis_mapping(self) -> None:
        with self.assertRaisesRegex(ValueError, "analysis.ai_max_tokens"):
            routes_tasks._resolve_chat_max_tokens({"analysis": "invalid"})

    def test_rejects_missing_setting(self) -> None:
        with self.assertRaisesRegex(ValueError, "analysis.ai_max_tokens"):
            routes_tasks._resolve_chat_max_tokens({"analysis": {}})

    def test_rejects_invalid_or_non_positive_values(self) -> None:
        invalid_configs = [
            {"analysis": {"ai_max_tokens": "abc"}},
            {"analysis": {"ai_max_tokens": 0}},
            {"analysis": {"ai_max_tokens": -5}},
        ]

        for config in invalid_configs:
            with self.subTest(config=config):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    routes_tasks._resolve_chat_max_tokens(config)


class CompressFindingsWithAiTests(unittest.TestCase):
    def test_returns_none_for_blank_findings(self) -> None:
        provider = MagicMock()

        result = routes_tasks._compress_findings_with_ai(provider, "   ", 1200)

        self.assertIsNone(result)
        provider.analyze.assert_not_called()

    @patch.object(routes_tasks, "_load_compress_findings_prompt", return_value="compress prompt")
    def test_uses_quarter_token_budget_and_strips_result(self, _mock_prompt: MagicMock) -> None:
        provider = MagicMock()
        provider.analyze.return_value = "  compressed findings  "

        result = routes_tasks._compress_findings_with_ai(provider, "- runkeys: suspicious entry", 1600)

        self.assertEqual(result, "compressed findings")
        provider.analyze.assert_called_once()
        self.assertEqual(provider.analyze.call_args.kwargs["system_prompt"], "compress prompt")
        self.assertEqual(provider.analyze.call_args.kwargs["max_tokens"], 400)
        self.assertIn("roughly 400 tokens", provider.analyze.call_args.kwargs["user_prompt"])
        self.assertIn("- runkeys: suspicious entry", provider.analyze.call_args.kwargs["user_prompt"])

    @patch.object(routes_tasks, "_load_compress_findings_prompt", return_value="compress prompt")
    def test_enforces_minimum_compression_budget(self, _mock_prompt: MagicMock) -> None:
        provider = MagicMock()
        provider.analyze.return_value = "compressed"

        routes_tasks._compress_findings_with_ai(provider, "- artifact: finding", 600)

        self.assertEqual(provider.analyze.call_args.kwargs["max_tokens"], 200)

    def test_returns_none_when_provider_returns_blank(self) -> None:
        provider = MagicMock()
        provider.analyze.return_value = "   "

        result = routes_tasks._compress_findings_with_ai(provider, "- artifact: finding", 1200)

        self.assertIsNone(result)

    def test_returns_none_when_provider_raises_ai_provider_error(self) -> None:
        provider = MagicMock()
        provider.analyze.side_effect = routes_tasks.AIProviderError("provider failed")

        result = routes_tasks._compress_findings_with_ai(provider, "- artifact: finding", 1200)

        self.assertIsNone(result)


class LoadCaseAnalysisResultsTests(unittest.TestCase):
    def test_invalid_json_on_disk_falls_back_to_in_memory_results(self) -> None:
        with TemporaryDirectory() as tmpdir:
            results_path = Path(tmpdir) / "analysis_results.json"
            results_path.write_text("{invalid json", encoding="utf-8")
            case = {
                "case_dir": tmpdir,
                "analysis_results": {"summary": "memory result", "per_artifact": []},
            }

            result = routes_tasks.load_case_analysis_results(case)

        self.assertEqual(result, {"summary": "memory result", "per_artifact": []})

    def test_non_mapping_results_on_disk_fall_back_to_in_memory_results(self) -> None:
        with TemporaryDirectory() as tmpdir:
            results_path = Path(tmpdir) / "analysis_results.json"
            results_path.write_text('["not", "a", "mapping"]', encoding="utf-8")
            case = {
                "case_dir": tmpdir,
                "analysis_results": {"summary": "memory result", "per_artifact": []},
            }

            result = routes_tasks.load_case_analysis_results(case)

        self.assertEqual(result, {"summary": "memory result", "per_artifact": []})


if __name__ == "__main__":
    unittest.main()
