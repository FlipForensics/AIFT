"""Tests for the Kimi AI provider implementation."""
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
    KimiProvider,
    DEFAULT_KIMI_MODEL,
    DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
)
from app.ai_providers.base import (
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    RATE_LIMIT_MAX_RETRIES,
)


def _make_openai_response(text: str) -> SimpleNamespace:
    """Build a minimal OpenAI-style chat completion response."""
    message = SimpleNamespace(content=text)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


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
    def test_analyze_stream_yields_text_chunks(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Chunk 1 "))]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Chunk 2"))]),
        ]

        provider = KimiProvider(
            api_key="sk-test",
            model=DEFAULT_KIMI_MODEL,
            base_url="https://api.moonshot.ai/v1",
        )
        chunks = list(provider.analyze_stream("system", "user"))

        self.assertEqual(chunks, ["Chunk 1 ", "Chunk 2"])
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertTrue(kwargs["stream"])
        self.assertEqual(kwargs["max_tokens"], 16384)

    @patch("openai.OpenAI")
    def test_analyze_stream_empty_response_raises(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=None))]),
        ]

        provider = KimiProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            list(provider.analyze_stream("system", "user"))
        self.assertIn("empty response", str(ctx.exception))

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

    def test_rejects_whitespace_api_key(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            KimiProvider(api_key="   ")
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
        mock_client.responses.create.side_effect = RuntimeError("unrecognized request url /responses")
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
        first_prompt = mock_client.chat.completions.create.call_args_list[0].kwargs["messages"][1]["content"]
        second_prompt = mock_client.chat.completions.create.call_args_list[1].kwargs["messages"][1]["content"]
        self.assertIn("File attachments were unavailable", first_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", first_prompt)
        self.assertIn("ts,name", first_prompt)
        self.assertIn("File attachments were unavailable", second_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", second_prompt)
        self.assertIn("ts,name", second_prompt)

    @patch("openai.OpenAI")
    def test_analyze_connection_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAPIConnectionError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = _FakeAPIConnectionError("connection refused")

        with patch("openai.APIConnectionError", _FakeAPIConnectionError):
            provider = KimiProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("Unable to connect", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_auth_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAuthError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = _FakeAuthError("invalid key")

        with patch("openai.AuthenticationError", _FakeAuthError):
            provider = KimiProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("authentication failed", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_model_not_available_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAPIError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = _FakeAPIError("model not found: kimi-custom")

        with patch("openai.APIError", _FakeAPIError):
            provider = KimiProvider(api_key="sk-test", model="kimi-custom")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("rejected the configured model", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_empty_response_raises(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[])

        provider = KimiProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        self.assertIn("empty response", str(ctx.exception))


# ---------------------------------------------------------------------------
# LocalProvider
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()
