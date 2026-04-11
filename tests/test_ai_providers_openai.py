"""Tests for the OpenAI AI provider implementation."""
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
    OpenAIProvider,
    _extract_openai_text,
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
    def test_analyze_stream_yields_text_chunks(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Chunk A "))]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Chunk B"))]),
        ]

        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        chunks = list(provider.analyze_stream("system", "user"))

        self.assertEqual(chunks, ["Chunk A ", "Chunk B"])
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertTrue(kwargs["stream"])

    @patch("openai.OpenAI")
    def test_analyze_stream_empty_response_raises(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=None))]),
        ]

        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
        with self.assertRaises(AIProviderError) as ctx:
            list(provider.analyze_stream("system", "user"))
        self.assertIn("empty response", str(ctx.exception))

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

    def test_rejects_whitespace_api_key(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            OpenAIProvider(api_key="   ")
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
        mock_client.responses.create.side_effect = RuntimeError("unrecognized request url /responses")
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

    @patch("openai.OpenAI")
    def test_analyze_connection_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAPIConnectionError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = _FakeAPIConnectionError("connection refused")

        with patch("openai.APIConnectionError", _FakeAPIConnectionError):
            provider = OpenAIProvider(api_key="sk-test")
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
            provider = OpenAIProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("authentication failed", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_context_length_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeBadRequestError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = _FakeBadRequestError("context_length_exceeded")

        with patch("openai.BadRequestError", _FakeBadRequestError):
            provider = OpenAIProvider(api_key="sk-test")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("context length", str(ctx.exception))



if __name__ == "__main__":
    unittest.main()
