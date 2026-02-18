"""Tests for app.ai_providers module."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.ai_providers import (
    AIProvider,
    AIProviderError,
    ClaudeProvider,
    DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
    DEFAULT_KIMI_MODEL,
    KimiProvider,
    LocalProvider,
    OpenAIProvider,
    _extract_anthropic_text,
    _extract_openai_text,
    _extract_retry_after_seconds,
    _is_context_length_error,
    _normalize_openai_compatible_base_url,
    _resolve_api_key,
    create_provider,
)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_anthropic_response(text: str) -> SimpleNamespace:
    """Build a minimal Anthropic-style response object."""
    block = SimpleNamespace(text=text)
    return SimpleNamespace(content=[block])


def _make_openai_response(text: str) -> SimpleNamespace:
    """Build a minimal OpenAI-style chat completion response."""
    message = SimpleNamespace(content=text)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


# ---------------------------------------------------------------------------
# _resolve_api_key
# ---------------------------------------------------------------------------

class TestResolveApiKey(unittest.TestCase):
    def test_returns_config_key_when_present(self) -> None:
        self.assertEqual(_resolve_api_key("sk-config", "DUMMY_VAR"), "sk-config")

    def test_falls_back_to_env_var(self) -> None:
        with patch.dict(os.environ, {"TEST_API_KEY": "sk-env"}):
            self.assertEqual(_resolve_api_key("", "TEST_API_KEY"), "sk-env")

    def test_returns_empty_when_neither_set(self) -> None:
        env = os.environ.copy()
        env.pop("MISSING_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(_resolve_api_key("", "MISSING_KEY"), "")


# ---------------------------------------------------------------------------
# _extract_retry_after_seconds
# ---------------------------------------------------------------------------

class TestExtractRetryAfter(unittest.TestCase):
    def test_extracts_from_response_headers(self) -> None:
        error = SimpleNamespace(
            response=SimpleNamespace(headers={"retry-after": "2.5"}),
        )
        self.assertEqual(_extract_retry_after_seconds(error), 2.5)

    def test_extracts_from_error_headers_directly(self) -> None:
        error = SimpleNamespace(
            response=None,
            headers={"Retry-After": "10"},
        )
        self.assertEqual(_extract_retry_after_seconds(error), 10.0)

    def test_returns_none_when_no_headers(self) -> None:
        error = SimpleNamespace(response=None)
        self.assertIsNone(_extract_retry_after_seconds(error))

    def test_returns_none_for_non_numeric_value(self) -> None:
        error = SimpleNamespace(
            response=SimpleNamespace(headers={"retry-after": "not-a-number"}),
        )
        self.assertIsNone(_extract_retry_after_seconds(error))

    def test_clamps_negative_to_zero(self) -> None:
        error = SimpleNamespace(
            response=SimpleNamespace(headers={"retry-after": "-5"}),
        )
        self.assertEqual(_extract_retry_after_seconds(error), 0.0)


# ---------------------------------------------------------------------------
# _is_context_length_error
# ---------------------------------------------------------------------------

class TestIsContextLengthError(unittest.TestCase):
    def test_detects_context_length_in_message(self) -> None:
        error = Exception("context_length_exceeded: max 128000 tokens")
        self.assertTrue(_is_context_length_error(error))

    def test_detects_too_many_tokens(self) -> None:
        error = Exception("Too many tokens in the request")
        self.assertTrue(_is_context_length_error(error))

    def test_detects_prompt_too_long(self) -> None:
        error = Exception("prompt is too long")
        self.assertTrue(_is_context_length_error(error))

    def test_false_for_unrelated_error(self) -> None:
        error = Exception("connection timeout")
        self.assertFalse(_is_context_length_error(error))

    def test_detects_from_error_code_attribute(self) -> None:
        error = Exception("bad request")
        error.code = "context_length_exceeded"
        self.assertTrue(_is_context_length_error(error))

    def test_detects_from_body_dict(self) -> None:
        error = Exception("error")
        error.body = {"error": {"message": "Maximum context length exceeded"}}
        self.assertTrue(_is_context_length_error(error))


# ---------------------------------------------------------------------------
# _normalize_openai_compatible_base_url
# ---------------------------------------------------------------------------

class TestNormalizeOpenAICompatibleBaseUrl(unittest.TestCase):
    def test_adds_v1_for_root_path(self) -> None:
        normalized = _normalize_openai_compatible_base_url(
            "http://localhost:11434/",
            "http://localhost:11434/v1",
        )
        self.assertEqual(normalized, "http://localhost:11434/v1")

    def test_keeps_existing_v1_path(self) -> None:
        normalized = _normalize_openai_compatible_base_url(
            "http://localhost:11434/v1/",
            "http://localhost:11434/v1",
        )
        self.assertEqual(normalized, "http://localhost:11434/v1")


# ---------------------------------------------------------------------------
# _extract_anthropic_text
# ---------------------------------------------------------------------------

class TestExtractAnthropicText(unittest.TestCase):
    def test_extracts_text_from_content_blocks(self) -> None:
        resp = _make_anthropic_response("Hello, world!")
        self.assertEqual(_extract_anthropic_text(resp), "Hello, world!")

    def test_concatenates_multiple_blocks(self) -> None:
        resp = SimpleNamespace(content=[
            SimpleNamespace(text="Part 1. "),
            SimpleNamespace(text="Part 2."),
        ])
        self.assertEqual(_extract_anthropic_text(resp), "Part 1. Part 2.")

    def test_handles_dict_blocks(self) -> None:
        resp = SimpleNamespace(content=[{"text": "dict block"}])
        self.assertEqual(_extract_anthropic_text(resp), "dict block")

    def test_returns_empty_for_no_content(self) -> None:
        resp = SimpleNamespace(content=None)
        self.assertEqual(_extract_anthropic_text(resp), "")

    def test_returns_empty_for_non_list_content(self) -> None:
        resp = SimpleNamespace(content="just a string")
        self.assertEqual(_extract_anthropic_text(resp), "")

    def test_skips_blocks_without_text(self) -> None:
        resp = SimpleNamespace(content=[
            SimpleNamespace(type="image"),
            SimpleNamespace(text="good"),
        ])
        self.assertEqual(_extract_anthropic_text(resp), "good")


# ---------------------------------------------------------------------------
# _extract_openai_text
# ---------------------------------------------------------------------------

class TestExtractOpenAIText(unittest.TestCase):
    def test_extracts_text_from_message_content(self) -> None:
        resp = _make_openai_response("Hello from GPT")
        self.assertEqual(_extract_openai_text(resp), "Hello from GPT")

    def test_returns_empty_for_no_choices(self) -> None:
        self.assertEqual(_extract_openai_text(SimpleNamespace(choices=[])), "")
        self.assertEqual(_extract_openai_text(SimpleNamespace(choices=None)), "")

    def test_handles_dict_message(self) -> None:
        choice = {"message": {"content": "from dict"}}
        resp = SimpleNamespace(choices=[choice])
        self.assertEqual(_extract_openai_text(resp), "from dict")

    def test_handles_list_content(self) -> None:
        message = SimpleNamespace(content=[
            SimpleNamespace(text="part1 "),
            {"text": "part2"},
        ])
        choice = SimpleNamespace(message=message)
        resp = SimpleNamespace(choices=[choice])
        self.assertEqual(_extract_openai_text(resp), "part1 part2")

    def test_returns_empty_for_none_message(self) -> None:
        choice = SimpleNamespace(message=None)
        resp = SimpleNamespace(choices=[choice])
        self.assertEqual(_extract_openai_text(resp), "")

    def test_falls_back_to_reasoning_content_when_content_empty(self) -> None:
        message = SimpleNamespace(content="", reasoning_content="Connection OK")
        choice = SimpleNamespace(message=message)
        resp = SimpleNamespace(choices=[choice])
        self.assertEqual(_extract_openai_text(resp), "Connection OK")

    def test_falls_back_to_refusal_when_content_empty(self) -> None:
        message = SimpleNamespace(content="", refusal="Request refused")
        choice = SimpleNamespace(message=message)
        resp = SimpleNamespace(choices=[choice])
        self.assertEqual(_extract_openai_text(resp), "Request refused")


# ---------------------------------------------------------------------------
# ClaudeProvider
# ---------------------------------------------------------------------------

class TestClaudeProvider(unittest.TestCase):
    @patch("anthropic.Anthropic")
    def test_analyze_returns_text(self, mock_anthropic_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _make_anthropic_response(
            "Analysis result"
        )

        provider = ClaudeProvider(api_key="sk-test", model="claude-sonnet-4-20250514")
        result = provider.analyze("system", "user")
        self.assertEqual(result, "Analysis result")

    @patch("anthropic.Anthropic")
    def test_get_model_info(self, _mock: MagicMock) -> None:
        provider = ClaudeProvider(api_key="sk-test", model="claude-sonnet-4-20250514")
        info = provider.get_model_info()
        self.assertEqual(info["provider"], "claude")
        self.assertEqual(info["model"], "claude-sonnet-4-20250514")

    def test_rejects_empty_api_key(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            ClaudeProvider(api_key="")
        self.assertIn("API key is not configured", str(ctx.exception))

    @patch("anthropic.Anthropic")
    def test_empty_response_raises(self, mock_anthropic_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = SimpleNamespace(content=[])

        provider = ClaudeProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        self.assertIn("empty response", str(ctx.exception))

    @patch("anthropic.Anthropic")
    def test_analyze_with_attachments_uses_document_blocks_when_supported(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _make_anthropic_response("Claude attachment result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")

            provider = ClaudeProvider(api_key="sk-test", model="claude-sonnet-4-20250514")
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "Claude attachment result")
        content = mock_client.messages.create.call_args.kwargs["messages"][0]["content"]
        self.assertIsInstance(content, list)
        self.assertEqual(content[1]["type"], "text")
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", content[1]["text"])

    @patch("anthropic.Anthropic")
    def test_analyze_with_attachments_falls_back_when_unsupported(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = [
            RuntimeError("unsupported document input"),
            _make_anthropic_response("Claude fallback result"),
            _make_anthropic_response("Claude fallback result second"),
        ]

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")
            attachments = [{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}]

            provider = ClaudeProvider(api_key="sk-test", model="claude-sonnet-4-20250514")
            first_result = provider.analyze_with_attachments("system", "user", attachments=attachments)
            second_result = provider.analyze_with_attachments("system", "user", attachments=attachments)

        self.assertEqual(first_result, "Claude fallback result")
        self.assertEqual(second_result, "Claude fallback result second")
        self.assertEqual(mock_client.messages.create.call_count, 3)
        self.assertEqual(
            mock_client.messages.create.call_args_list[1].kwargs["messages"][0]["content"],
            "user",
        )

    @patch("anthropic.Anthropic")
    def test_analyze_retries_with_stream_for_long_requests(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = ValueError(
            "Streaming is required for operations that may take longer than 10 minutes. "
            "See https://github.com/anthropics/anthropic-sdk-python#long-requests for more details"
        )
        stream_obj = MagicMock()
        stream_obj.get_final_message.return_value = _make_anthropic_response("Claude streamed result")
        stream_ctx = MagicMock()
        stream_ctx.__enter__.return_value = stream_obj
        stream_ctx.__exit__.return_value = None
        mock_client.messages.stream.return_value = stream_ctx

        provider = ClaudeProvider(api_key="sk-test", model="claude-opus-4-6")
        result = provider.analyze("system", "user", max_tokens=256000)

        self.assertEqual(result, "Claude streamed result")
        self.assertEqual(mock_client.messages.create.call_count, 1)
        self.assertEqual(mock_client.messages.stream.call_count, 1)
        stream_kwargs = mock_client.messages.stream.call_args.kwargs
        self.assertEqual(stream_kwargs["max_tokens"], 256000)
        self.assertEqual(stream_kwargs["messages"][0]["content"], "user")

    @patch("anthropic.Anthropic")
    def test_analyze_with_attachments_retries_with_stream_for_long_requests(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = ValueError(
            "Streaming is required for operations that may take longer than 10 minutes. "
            "See https://github.com/anthropics/anthropic-sdk-python#long-requests for more details"
        )
        stream_obj = MagicMock()
        stream_obj.get_final_message.return_value = _make_anthropic_response("Claude attachment streamed result")
        stream_ctx = MagicMock()
        stream_ctx.__enter__.return_value = stream_obj
        stream_ctx.__exit__.return_value = None
        mock_client.messages.stream.return_value = stream_ctx

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")

            provider = ClaudeProvider(api_key="sk-test", model="claude-opus-4-6")
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}],
                max_tokens=256000,
            )

        self.assertEqual(result, "Claude attachment streamed result")
        self.assertEqual(mock_client.messages.create.call_count, 1)
        self.assertEqual(mock_client.messages.stream.call_count, 1)
        stream_kwargs = mock_client.messages.stream.call_args.kwargs
        content_blocks = stream_kwargs["messages"][0]["content"]
        self.assertIsInstance(content_blocks, list)
        self.assertEqual(content_blocks[0]["type"], "text")
        self.assertEqual(content_blocks[1]["type"], "text")
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", content_blocks[1]["text"])

    @patch("anthropic.Anthropic")
    def test_analyze_retries_with_model_token_cap_when_max_tokens_too_large(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        class _FakeBadRequestError(Exception):
            pass

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = [
            _FakeBadRequestError(
                "maxtokens: 256000 > 128000, which is the maximum allowed number of output tokens for claude-opus-4-6"
            ),
            _make_anthropic_response("Claude capped result"),
        ]

        with patch("anthropic.BadRequestError", _FakeBadRequestError):
            provider = ClaudeProvider(api_key="sk-test", model="claude-opus-4-6")
            result = provider.analyze("system", "user", max_tokens=256000)

        self.assertEqual(result, "Claude capped result")
        self.assertEqual(mock_client.messages.create.call_count, 2)
        first_kwargs = mock_client.messages.create.call_args_list[0].kwargs
        second_kwargs = mock_client.messages.create.call_args_list[1].kwargs
        self.assertEqual(first_kwargs["max_tokens"], 256000)
        self.assertEqual(second_kwargs["max_tokens"], 128000)

    @patch("anthropic.Anthropic")
    def test_analyze_stream_retries_with_model_token_cap_when_max_tokens_too_large(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        class _FakeBadRequestError(Exception):
            pass

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = ValueError(
            "Streaming is required for operations that may take longer than 10 minutes. "
            "See https://github.com/anthropics/anthropic-sdk-python#long-requests for more details"
        )

        stream_obj = MagicMock()
        stream_obj.get_final_message.return_value = _make_anthropic_response("Claude streamed capped result")
        stream_ctx = MagicMock()
        stream_ctx.__enter__.return_value = stream_obj
        stream_ctx.__exit__.return_value = None
        mock_client.messages.stream.side_effect = [
            _FakeBadRequestError(
                "maxtokens: 256000 > 128000, which is the maximum allowed number of output tokens for claude-opus-4-6"
            ),
            stream_ctx,
        ]

        with patch("anthropic.BadRequestError", _FakeBadRequestError):
            provider = ClaudeProvider(api_key="sk-test", model="claude-opus-4-6")
            result = provider.analyze("system", "user", max_tokens=256000)

        self.assertEqual(result, "Claude streamed capped result")
        self.assertEqual(mock_client.messages.create.call_count, 1)
        self.assertEqual(mock_client.messages.stream.call_count, 2)
        first_stream_kwargs = mock_client.messages.stream.call_args_list[0].kwargs
        second_stream_kwargs = mock_client.messages.stream.call_args_list[1].kwargs
        self.assertEqual(first_stream_kwargs["max_tokens"], 256000)
        self.assertEqual(second_stream_kwargs["max_tokens"], 128000)


# ---------------------------------------------------------------------------
# OpenAIProvider
# ---------------------------------------------------------------------------

class TestOpenAIProvider(unittest.TestCase):
    @patch("openai.OpenAI")
    def test_analyze_returns_text(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response(
            "GPT result"
        )

        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        result = provider.analyze("system", "user")
        self.assertEqual(result, "GPT result")

    @patch("openai.OpenAI")
    def test_analyze_prefers_max_completion_tokens(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response("GPT result")

        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        provider.analyze("system", "user", max_tokens=321)

        kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertEqual(kwargs["max_completion_tokens"], 321)
        self.assertNotIn("max_tokens", kwargs)

    @patch("openai.OpenAI")
    def test_analyze_falls_back_to_max_tokens_when_max_completion_tokens_unsupported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        class _FakeBadRequestError(Exception):
            def __init__(self, message: str, *, param: str | None = None) -> None:
                super().__init__(message)
                self.param = param
                self.body = {"error": {"message": message, "param": param}}

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = [
            _FakeBadRequestError(
                "Unsupported parameter: 'max_completion_tokens'.",
                param="max_completion_tokens",
            ),
            _make_openai_response("GPT fallback result"),
        ]

        with patch("openai.BadRequestError", _FakeBadRequestError):
            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
            result = provider.analyze("system", "user", max_tokens=222)

        self.assertEqual(result, "GPT fallback result")
        self.assertEqual(mock_client.chat.completions.create.call_count, 2)
        first_kwargs = mock_client.chat.completions.create.call_args_list[0].kwargs
        second_kwargs = mock_client.chat.completions.create.call_args_list[1].kwargs
        self.assertEqual(first_kwargs["max_completion_tokens"], 222)
        self.assertNotIn("max_tokens", first_kwargs)
        self.assertEqual(second_kwargs["max_tokens"], 222)
        self.assertNotIn("max_completion_tokens", second_kwargs)

    @patch("openai.OpenAI")
    def test_analyze_retries_with_model_token_cap_when_max_tokens_too_large(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        class _FakeBadRequestError(Exception):
            def __init__(self, message: str, *, param: str | None = None) -> None:
                super().__init__(message)
                self.param = param
                self.body = {"error": {"message": message, "param": param}}

        max_tokens_error = _FakeBadRequestError(
            "maxtokens is too large: 256000. This model supports at most 128000 completion tokens, whereas you provided 256000.",
            param="maxtokens",
        )
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = [
            max_tokens_error,
            _make_openai_response("GPT capped result"),
        ]

        with patch("openai.BadRequestError", _FakeBadRequestError):
            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
            result = provider.analyze("system", "user", max_tokens=256000)

        self.assertEqual(result, "GPT capped result")
        self.assertEqual(mock_client.chat.completions.create.call_count, 2)
        first_kwargs = mock_client.chat.completions.create.call_args_list[0].kwargs
        second_kwargs = mock_client.chat.completions.create.call_args_list[1].kwargs
        self.assertEqual(first_kwargs["max_completion_tokens"], 256000)
        self.assertEqual(second_kwargs["max_completion_tokens"], 128000)

    @patch("openai.OpenAI")
    def test_get_model_info(self, _mock: MagicMock) -> None:
        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        info = provider.get_model_info()
        self.assertEqual(info["provider"], "openai")
        self.assertEqual(info["model"], "gpt-4o")

    def test_rejects_empty_api_key(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            OpenAIProvider(api_key="")
        self.assertIn("API key is not configured", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_uses_responses_api_when_supported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-123")
        mock_client.responses.create.return_value = SimpleNamespace(output_text="OpenAI attachment result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")

            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "OpenAI attachment result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertEqual(mock_client.files.delete.call_count, 1)
        upload_file = mock_client.files.create.call_args.kwargs["file"]
        self.assertEqual(upload_file[0], "runkeys.txt")
        self.assertEqual(upload_file[2], "text/plain")

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_retries_with_model_token_cap_when_too_large(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        class _FakeBadRequestError(Exception):
            def __init__(self, message: str, *, param: str | None = None) -> None:
                super().__init__(message)
                self.param = param
                self.body = {"error": {"message": message, "param": param}}

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-123")
        mock_client.responses.create.side_effect = [
            _FakeBadRequestError(
                "maxtokens is too large: 256000. This model supports at most 128000 completion tokens, whereas you provided 256000.",
                param="maxtokens",
            ),
            SimpleNamespace(output_text="OpenAI attachment result"),
        ]

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")

            with patch("openai.BadRequestError", _FakeBadRequestError):
                provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
                result = provider.analyze_with_attachments(
                    "system",
                    "user",
                    attachments=[{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}],
                    max_tokens=256000,
                )

        self.assertEqual(result, "OpenAI attachment result")
        self.assertEqual(mock_client.responses.create.call_count, 2)
        first_kwargs = mock_client.responses.create.call_args_list[0].kwargs
        second_kwargs = mock_client.responses.create.call_args_list[1].kwargs
        self.assertEqual(first_kwargs["max_output_tokens"], 256000)
        self.assertEqual(second_kwargs["max_output_tokens"], 128000)
        self.assertEqual(mock_client.chat.completions.create.call_count, 0)

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_falls_back_when_endpoint_unsupported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-unsupported")
        mock_client.responses.create.side_effect = RuntimeError("404 page not found")
        mock_client.chat.completions.create.return_value = _make_openai_response("OpenAI fallback result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")
            attachments = [{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}]

            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
            first_result = provider.analyze_with_attachments("system", "user", attachments=attachments)
            second_result = provider.analyze_with_attachments("system", "user", attachments=attachments)

        self.assertEqual(first_result, "OpenAI fallback result")
        self.assertEqual(second_result, "OpenAI fallback result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertGreaterEqual(mock_client.chat.completions.create.call_count, 2)
        first_prompt = mock_client.chat.completions.create.call_args_list[0].kwargs["messages"][1]["content"]
        second_prompt = mock_client.chat.completions.create.call_args_list[1].kwargs["messages"][1]["content"]
        self.assertIn("File attachments were unavailable", first_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", first_prompt)
        self.assertIn("ts,name", first_prompt)
        self.assertIn("File attachments were unavailable", second_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", second_prompt)
        self.assertIn("ts,name", second_prompt)

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_falls_back_when_csv_file_type_rejected(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-unsupported")
        mock_client.responses.create.side_effect = RuntimeError(
            "Invalid input: Expected context stuffing file type to be a supported format but got .csv."
        )
        mock_client.chat.completions.create.return_value = _make_openai_response("OpenAI fallback result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")
            attachments = [{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}]

            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
            result = provider.analyze_with_attachments("system", "user", attachments=attachments)

        self.assertEqual(result, "OpenAI fallback result")
        upload_file = mock_client.files.create.call_args.kwargs["file"]
        self.assertEqual(upload_file[0], "runkeys.txt")
        self.assertEqual(upload_file[2], "text/plain")
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertEqual(mock_client.chat.completions.create.call_count, 1)
        fallback_prompt = mock_client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("File attachments were unavailable", fallback_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", fallback_prompt)
        self.assertIn("ts,name", fallback_prompt)


# ---------------------------------------------------------------------------
# KimiProvider
# ---------------------------------------------------------------------------

class TestKimiProvider(unittest.TestCase):
    @patch("openai.OpenAI")
    def test_analyze_returns_text(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response(
            "Kimi result"
        )

        provider = KimiProvider(
            api_key="sk-test",
            model=DEFAULT_KIMI_MODEL,
            base_url="https://api.moonshot.ai/v1",
        )
        result = provider.analyze("system", "user")
        self.assertEqual(result, "Kimi result")

    @patch("openai.OpenAI")
    def test_get_model_info(self, _mock: MagicMock) -> None:
        provider = KimiProvider(
            api_key="sk-test",
            model=DEFAULT_KIMI_MODEL,
            base_url="https://api.moonshot.ai/v1",
        )
        info = provider.get_model_info()
        self.assertEqual(info["provider"], "kimi")
        self.assertEqual(info["model"], DEFAULT_KIMI_MODEL)

    @patch("openai.OpenAI")
    def test_normalizes_deprecated_model_alias(self, _mock: MagicMock) -> None:
        provider = KimiProvider(
            api_key="sk-test",
            model="kimi-v2.5",
            base_url="https://api.moonshot.ai/v1",
        )
        self.assertEqual(provider.model, DEFAULT_KIMI_MODEL)

    def test_rejects_empty_api_key(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            KimiProvider(api_key="")
        self.assertIn("API key is not configured", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_uses_responses_api_when_supported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-123")
        mock_client.responses.create.return_value = SimpleNamespace(output_text="Kimi attachment result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")

            provider = KimiProvider(
                api_key="sk-test",
                model=DEFAULT_KIMI_MODEL,
                base_url="https://api.moonshot.ai/v1",
            )
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "Kimi attachment result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(
            mock_client.files.create.call_args.kwargs["purpose"],
            DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
        )
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertEqual(mock_client.files.delete.call_count, 1)

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_falls_back_when_endpoint_unsupported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-unsupported")
        mock_client.responses.create.side_effect = RuntimeError("404 page not found")
        mock_client.chat.completions.create.return_value = _make_openai_response("Kimi fallback result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")
            attachments = [{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}]

            provider = KimiProvider(
                api_key="sk-test",
                model=DEFAULT_KIMI_MODEL,
                base_url="https://api.moonshot.ai/v1",
            )
            first_result = provider.analyze_with_attachments("system", "user", attachments=attachments)
            second_result = provider.analyze_with_attachments("system", "user", attachments=attachments)

        self.assertEqual(first_result, "Kimi fallback result")
        self.assertEqual(second_result, "Kimi fallback result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertGreaterEqual(mock_client.chat.completions.create.call_count, 2)


# ---------------------------------------------------------------------------
# LocalProvider
# ---------------------------------------------------------------------------

class TestLocalProvider(unittest.TestCase):
    @patch("openai.OpenAI")
    def test_analyze_returns_text(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response(
            "Local result"
        )

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        result = provider.analyze("system", "user")
        self.assertEqual(result, "Local result")

    @patch("openai.OpenAI")
    def test_get_model_info(self, _mock: MagicMock) -> None:
        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        info = provider.get_model_info()
        self.assertEqual(info["provider"], "local")
        self.assertEqual(info["model"], "llama3.1:70b")

    @patch("openai.OpenAI")
    def test_default_api_key(self, mock_openai_cls: MagicMock) -> None:
        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        self.assertEqual(provider.api_key, "not-needed")

    @patch("openai.OpenAI")
    def test_normalizes_root_base_url_to_v1(self, mock_openai_cls: MagicMock) -> None:
        LocalProvider(base_url="http://localhost:11434/", model="llama3.1:70b")
        kwargs = mock_openai_cls.call_args.kwargs
        self.assertEqual(kwargs["base_url"], "http://localhost:11434/v1")

    @patch("openai.OpenAI")
    def test_analyze_with_progress_streams_thinking_and_returns_final_text(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        chunk1 = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(reasoning="Thinking step 1. "),
                )
            ]
        )
        chunk2 = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(content="Final answer."),
                )
            ]
        )
        mock_client.chat.completions.create.return_value = [chunk1, chunk2]

        progress_updates: list[dict[str, str]] = []
        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        result = provider.analyze_with_progress(
            "system",
            "user",
            progress_callback=lambda payload: progress_updates.append(payload),
        )

        self.assertEqual(result, "Final answer.")
        self.assertTrue(progress_updates)
        self.assertEqual(progress_updates[-1]["status"], "thinking")
        self.assertIn("Thinking step 1.", progress_updates[-1]["thinking_text"])

    @patch("openai.OpenAI")
    def test_analyze_with_progress_removes_streamed_reasoning_prefix_from_final_answer(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        reasoning_text = "I will reason through all artifact records before answering. "
        chunk1 = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(reasoning=reasoning_text),
                )
            ]
        )
        chunk2 = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(content=reasoning_text),
                )
            ]
        )
        chunk3 = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(content="### Findings\n- Suspicious autorun entry."),
                )
            ]
        )
        mock_client.chat.completions.create.return_value = [chunk1, chunk2, chunk3]

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        result = provider.analyze_with_progress(
            "system",
            "user",
            progress_callback=lambda _payload: None,
        )

        self.assertEqual(result, "### Findings\n- Suspicious autorun entry.")

    @patch("openai.OpenAI")
    def test_analyze_with_progress_strips_leading_think_block_from_final_answer(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        chunk = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        content="<think>\ninternal reasoning\n</think>\n\n### Findings\n- Final answer."
                    ),
                )
            ]
        )
        mock_client.chat.completions.create.return_value = [chunk]

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        result = provider.analyze_with_progress(
            "system",
            "user",
            progress_callback=lambda _payload: None,
        )

        self.assertEqual(result, "### Findings\n- Final answer.")
        self.assertNotIn("<think>", result)

    @patch("openai.OpenAI")
    def test_analyze_strips_leading_think_block_in_non_stream_mode(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response(
            "<think>\nhidden chain-of-thought\n</think>\n\nFinal answer."
        )

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        result = provider.analyze("system", "user")

        self.assertEqual(result, "Final answer.")

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_uses_responses_api_when_supported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-123")
        mock_client.responses.create.return_value = SimpleNamespace(output_text="Attachment result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")

            provider = LocalProvider(
                base_url="http://localhost:11434/v1", model="llama3.1:70b"
            )
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "Attachment result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertEqual(mock_client.files.delete.call_count, 1)

    @patch("openai.OpenAI")
    def test_analyze_with_attachments_falls_back_when_endpoint_unsupported(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-unsupported")
        mock_client.responses.create.side_effect = RuntimeError("404 page not found")
        mock_client.chat.completions.create.return_value = _make_openai_response("Fallback result")

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")
            attachments = [{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}]

            provider = LocalProvider(
                base_url="http://localhost:11434/v1", model="llama3.1:70b"
            )
            first_result = provider.analyze_with_attachments("system", "user", attachments=attachments)
            second_result = provider.analyze_with_attachments("system", "user", attachments=attachments)

        self.assertEqual(first_result, "Fallback result")
        self.assertEqual(second_result, "Fallback result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertGreaterEqual(mock_client.chat.completions.create.call_count, 2)


# ---------------------------------------------------------------------------
# create_provider factory
# ---------------------------------------------------------------------------

class TestCreateProvider(unittest.TestCase):
    @patch("anthropic.Anthropic")
    def test_creates_claude_provider(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "claude",
                "claude": {"api_key": "sk-test", "model": "claude-sonnet-4-20250514"},
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, ClaudeProvider)
        self.assertEqual(provider.model, "claude-sonnet-4-20250514")

    @patch("anthropic.Anthropic")
    def test_creates_claude_provider_with_attachment_flag(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "claude",
                "claude": {
                    "api_key": "sk-test",
                    "model": "claude-sonnet-4-20250514",
                    "attach_csv_as_file": False,
                },
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, ClaudeProvider)
        self.assertFalse(provider.attach_csv_as_file)

    @patch("openai.OpenAI")
    def test_creates_openai_provider(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "openai",
                "openai": {"api_key": "sk-test", "model": "gpt-4o"},
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, OpenAIProvider)

    @patch("openai.OpenAI")
    def test_creates_openai_provider_with_attachment_flag(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "openai",
                "openai": {"api_key": "sk-test", "model": "gpt-4o", "attach_csv_as_file": False},
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertFalse(provider.attach_csv_as_file)

    @patch("openai.OpenAI")
    def test_creates_local_provider(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "local",
                "local": {
                    "base_url": "http://localhost:11434/v1",
                    "model": "llama3.1:70b",
                },
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, LocalProvider)

    @patch("openai.OpenAI")
    def test_creates_local_provider_with_attachment_flag(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "local",
                "local": {
                    "base_url": "http://localhost:11434/v1",
                    "model": "llama3.1:70b",
                    "attach_csv_as_file": False,
                },
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, LocalProvider)
        self.assertFalse(provider.attach_csv_as_file)

    @patch("openai.OpenAI")
    def test_creates_kimi_provider(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "kimi",
                "kimi": {
                    "api_key": "sk-test",
                    "model": "kimi-v2.5",
                    "base_url": "https://api.moonshot.ai/v1",
                },
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider.model, DEFAULT_KIMI_MODEL)

    @patch("openai.OpenAI")
    def test_creates_kimi_provider_with_attachment_flag(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "kimi",
                "kimi": {
                    "api_key": "sk-test",
                    "model": DEFAULT_KIMI_MODEL,
                    "base_url": "https://api.moonshot.ai/v1",
                    "attach_csv_as_file": False,
                },
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertFalse(provider.attach_csv_as_file)

    def test_raises_on_unsupported_provider(self) -> None:
        config = {"ai": {"provider": "gemini"}}
        with self.assertRaises(ValueError) as ctx:
            create_provider(config)
        self.assertIn("gemini", str(ctx.exception))

    def test_raises_on_invalid_ai_section(self) -> None:
        config = {"ai": "not a dict"}
        with self.assertRaises(ValueError):
            create_provider(config)

    @patch("anthropic.Anthropic")
    def test_defaults_to_claude_when_no_provider_set(self, _mock: MagicMock) -> None:
        config = {"ai": {"claude": {"api_key": "sk-test"}}}
        provider = create_provider(config)
        self.assertIsInstance(provider, ClaudeProvider)

    @patch("anthropic.Anthropic")
    def test_env_var_fallback_for_claude(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "claude", "claude": {"api_key": ""}}}
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, ClaudeProvider)
        self.assertEqual(provider.api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_openai(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "openai", "openai": {"api_key": ""}}}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertEqual(provider.api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_kimi(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "kimi", "kimi": {"api_key": ""}}}
        with patch.dict(os.environ, {"MOONSHOT_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider.api_key, "sk-from-env")


# ---------------------------------------------------------------------------
# AIProviderError pass-through (double-wrapping bug fix)
# ---------------------------------------------------------------------------

class TestAIProviderErrorPassthrough(unittest.TestCase):
    """Verify that AIProviderError raised inside _request() is not re-wrapped."""

    @patch("anthropic.Anthropic")
    def test_claude_empty_response_not_double_wrapped(
        self, mock_anthropic_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = SimpleNamespace(content=[])

        provider = ClaudeProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        # Should say "empty response", NOT "Unexpected Claude provider error: ..."
        self.assertIn("empty response", str(ctx.exception))
        self.assertNotIn("Unexpected", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_openai_empty_response_not_double_wrapped(
        self, mock_openai_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[])

        provider = OpenAIProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        self.assertIn("empty response", str(ctx.exception))
        self.assertNotIn("Unexpected", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_local_empty_response_not_double_wrapped(
        self, mock_openai_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[])

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="test-model"
        )
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        self.assertIn("empty response", str(ctx.exception))
        self.assertNotIn("Unexpected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
