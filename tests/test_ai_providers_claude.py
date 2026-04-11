"""Tests for the Claude AI provider implementation."""
from __future__ import annotations

import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

from app.ai_providers import (
    AIProviderError,
    ClaudeProvider,
    _extract_anthropic_text,
)
from app.ai_providers.base import (
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    RATE_LIMIT_MAX_RETRIES,
)


def _make_anthropic_response(text: str) -> SimpleNamespace:
    """Build a minimal Anthropic-style response object."""
    block = SimpleNamespace(text=text)
    return SimpleNamespace(content=[block])


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
    def test_analyze_stream_yields_text_chunks(self, mock_anthropic_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = [
            SimpleNamespace(
                type="content_block_delta",
                delta=SimpleNamespace(text="Chunk 1 "),
            ),
            SimpleNamespace(
                type="content_block_delta",
                delta=SimpleNamespace(text="Chunk 2"),
            ),
        ]

        provider = ClaudeProvider(api_key="sk-test", model="claude-sonnet-4-20250514")
        chunks = list(provider.analyze_stream("system", "user"))

        self.assertEqual(chunks, ["Chunk 1 ", "Chunk 2"])
        kwargs = mock_client.messages.create.call_args.kwargs
        self.assertTrue(kwargs["stream"])

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

    def test_rejects_whitespace_api_key(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            ClaudeProvider(api_key="   ")
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
    def test_analyze_stream_empty_response_raises(self, mock_anthropic_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = [
            SimpleNamespace(type="message_stop"),
        ]

        provider = ClaudeProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            list(provider.analyze_stream("system", "user"))
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
        fallback_prompt = mock_client.messages.create.call_args_list[1].kwargs["messages"][0]["content"]
        self.assertIn("File attachments were unavailable", fallback_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", fallback_prompt)
        self.assertIn("ts,name", fallback_prompt)

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

    @patch("anthropic.Anthropic")
    def test_analyze_connection_error(self, mock_anthropic_cls: MagicMock) -> None:
        class _FakeAPIConnectionError(Exception):
            pass

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = _FakeAPIConnectionError("connection failed")

        with patch("anthropic.APIConnectionError", _FakeAPIConnectionError):
            provider = ClaudeProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("Unable to connect", str(ctx.exception))

    @patch("anthropic.Anthropic")
    def test_analyze_auth_error(self, mock_anthropic_cls: MagicMock) -> None:
        class _FakeAuthError(Exception):
            pass

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = _FakeAuthError("invalid key")

        with patch("anthropic.AuthenticationError", _FakeAuthError):
            provider = ClaudeProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("authentication failed", str(ctx.exception))

    @patch("anthropic.Anthropic")
    def test_analyze_bad_request_context_length(self, mock_anthropic_cls: MagicMock) -> None:
        class _FakeBadRequestError(Exception):
            pass

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = _FakeBadRequestError("context_length_exceeded")

        with patch("anthropic.BadRequestError", _FakeBadRequestError):
            provider = ClaudeProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("context length", str(ctx.exception))

    @patch("anthropic.Anthropic")
    def test_analyze_with_pdf_attachment(self, mock_anthropic_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _make_anthropic_response("PDF result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            pdf_path = Path(tmp) / "doc.pdf"
            pdf_path.write_bytes(b"%PDF-1.4 fake pdf content")

            provider = ClaudeProvider(api_key="sk-test")
            result = provider.analyze_with_attachments(
                "system", "user",
                attachments=[{"path": str(pdf_path), "name": "doc.pdf", "mime_type": "application/pdf"}],
            )

        self.assertEqual(result, "PDF result")
        content = mock_client.messages.create.call_args.kwargs["messages"][0]["content"]
        self.assertIsInstance(content, list)
        self.assertEqual(content[1]["type"], "document")
        self.assertEqual(content[1]["source"]["media_type"], "application/pdf")



if __name__ == "__main__":
    unittest.main()
