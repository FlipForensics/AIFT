"""Tests for the Local AI provider implementation and provider factory.

Covers TestLocalProvider and its helper classes (stream chunks, progress,
finalize, chat prompt), TestCreateProvider factory, TestAIProviderErrorPassthrough,
TestUploadAndRequestViaResponsesAPI, and TestAttachmentFallbackRegression.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

from app.ai_providers import (
    AIProvider,
    AIProviderError,
    ClaudeProvider,
    KimiProvider,
    LocalProvider,
    OpenAIProvider,
    _extract_openai_text,
    create_provider,
)
from app.ai_providers.base import (
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    RATE_LIMIT_MAX_RETRIES,
)
from app.ai_providers.utils import (
    upload_and_request_via_responses_api,
    _inline_attachment_data_into_prompt,
)


def _make_openai_response(text: str) -> SimpleNamespace:
    """Build a minimal OpenAI-style chat completion response."""
    message = SimpleNamespace(content=text)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


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
    def test_analyze_stream_yields_text_chunks(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Local chunk 1 "))]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Local chunk 2"))]),
        ]

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="llama3.1:70b"
        )
        chunks = list(provider.analyze_stream("system", "user"))

        self.assertEqual(chunks, ["Local chunk 1 ", "Local chunk 2"])
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertTrue(kwargs["stream"])

    @patch("openai.OpenAI")
    def test_analyze_stream_empty_response_raises(self, mock_openai_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=None))]),
        ]

        provider = LocalProvider(base_url="http://localhost:11434/v1", model="test")
        with self.assertRaises(AIProviderError) as ctx:
            list(provider.analyze_stream("system", "user"))
        self.assertIn("empty", str(ctx.exception).lower())

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
        self.assertEqual(provider._api_key, "not-needed")

    @patch("openai.OpenAI")
    def test_normalizes_root_base_url_to_v1(self, mock_openai_cls: MagicMock) -> None:
        LocalProvider(base_url="http://localhost:11434/", model="llama3.1:70b")
        kwargs = mock_openai_cls.call_args.kwargs
        self.assertEqual(kwargs["base_url"], "http://localhost:11434/v1")

    @patch("openai.OpenAI")
    def test_uses_configured_timeout_and_disables_internal_retries(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        LocalProvider(
            base_url="http://localhost:11434/v1",
            model="llama3.1:70b",
            request_timeout_seconds=7200,
        )
        kwargs = mock_openai_cls.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 7200.0)
        self.assertEqual(kwargs["max_retries"], 0)

    @patch("openai.OpenAI")
    def test_timeout_errors_surface_timeout_guidance(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        class _FakeAPIConnectionError(Exception):
            pass

        class _FakeAPITimeoutError(_FakeAPIConnectionError):
            pass

        with patch("openai.APIConnectionError", _FakeAPIConnectionError), patch(
            "openai.APITimeoutError",
            _FakeAPITimeoutError,
        ):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="llama3.1:70b",
                request_timeout_seconds=1800,
            )
            mock_client.chat.completions.create.side_effect = _FakeAPITimeoutError(
                "request timed out"
            )

            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")

        self.assertIn("timed out after 1800 seconds", str(ctx.exception))
        self.assertIn("ai.local.request_timeout_seconds", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_connection_error_without_timeout(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAPIConnectionError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        with patch("openai.APIConnectionError", _FakeAPIConnectionError):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="llama3.1:70b",
            )
            mock_client.chat.completions.create.side_effect = _FakeAPIConnectionError(
                "connection refused"
            )
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("Unable to connect", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_auth_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAuthError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        with patch("openai.AuthenticationError", _FakeAuthError):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
            )
            mock_client.chat.completions.create.side_effect = _FakeAuthError("bad key")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("rejected authentication", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_api_error_404(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAPIError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        with patch("openai.APIError", _FakeAPIError):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
            )
            mock_client.chat.completions.create.side_effect = _FakeAPIError("404 not found")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("404", str(ctx.exception))
            self.assertIn("base URL", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_api_error_generic(self, mock_openai_cls: MagicMock) -> None:
        class _FakeAPIError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        with patch("openai.APIError", _FakeAPIError):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
            )
            mock_client.chat.completions.create.side_effect = _FakeAPIError("internal server error")
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("Local provider API error", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_context_length_error(self, mock_openai_cls: MagicMock) -> None:
        class _FakeBadRequestError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        with patch("openai.BadRequestError", _FakeBadRequestError):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
            )
            mock_client.chat.completions.create.side_effect = _FakeBadRequestError(
                "context_length_exceeded"
            )
            with self.assertRaises(AIProviderError) as ctx:
                provider.analyze("system", "user")
            self.assertIn("context length", str(ctx.exception))

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
    def test_analyze_with_progress_with_attachments_falls_back_to_stream_with_inlined_prompt(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-unsupported")
        mock_client.responses.create.side_effect = RuntimeError("unrecognized request url /responses")
        chunk = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(content="Local streamed fallback result"),
                )
            ]
        )
        mock_client.chat.completions.create.return_value = [chunk]

        with TemporaryDirectory(prefix="aift-ai-provider-test-") as temp_dir:
            csv_path = Path(temp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2026-01-15T12:00:00Z,EntryA\n", encoding="utf-8")
            attachments = [{"path": str(csv_path), "name": "runkeys.csv", "mime_type": "text/csv"}]

            provider = LocalProvider(
                base_url="http://localhost:11434/v1", model="llama3.1:70b"
            )
            result = provider.analyze_with_progress(
                "system",
                "user",
                progress_callback=lambda _payload: None,
                attachments=attachments,
            )

        self.assertEqual(result, "Local streamed fallback result")
        self.assertEqual(mock_client.files.create.call_count, 1)
        self.assertEqual(mock_client.responses.create.call_count, 1)
        self.assertEqual(mock_client.chat.completions.create.call_count, 1)
        stream_kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertTrue(stream_kwargs["stream"])
        stream_prompt = stream_kwargs["messages"][1]["content"]
        self.assertIn("File attachments were unavailable", stream_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", stream_prompt)
        self.assertIn("ts,name", stream_prompt)

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
        mock_client.responses.create.side_effect = RuntimeError("unrecognized request url /responses")
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
        first_prompt = mock_client.chat.completions.create.call_args_list[0].kwargs["messages"][1]["content"]
        second_prompt = mock_client.chat.completions.create.call_args_list[1].kwargs["messages"][1]["content"]
        self.assertIn("File attachments were unavailable", first_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", first_prompt)
        self.assertIn("ts,name", first_prompt)
        self.assertIn("File attachments were unavailable", second_prompt)
        self.assertIn("--- BEGIN ATTACHMENT: runkeys.csv ---", second_prompt)
        self.assertIn("ts,name", second_prompt)

    @patch("openai.OpenAI")
    def test_analyze_with_progress_no_callback_delegates_to_analyze_with_attachments(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response("result")

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="test"
        )
        result = provider.analyze_with_progress(
            "system", "user", progress_callback=None
        )
        self.assertEqual(result, "result")

    @patch("openai.OpenAI")
    def test_analyze_non_stream_empty_with_finish_reason(
        self, mock_openai_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        choice = SimpleNamespace(
            message=SimpleNamespace(content=""),
            finish_reason="length",
        )
        mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[choice])

        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="test"
        )
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        self.assertIn("finish_reason=length", str(ctx.exception))

    @patch("openai.OpenAI")
    def test_analyze_stream_falls_back_to_non_stream_when_unsupported(
        self, mock_openai_cls: MagicMock
    ) -> None:
        class _FakeBadRequestError(Exception):
            pass

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = [
            _FakeBadRequestError("stream is not supported by this endpoint"),
            _make_openai_response("Non-stream fallback"),
        ]

        with patch("openai.BadRequestError", _FakeBadRequestError):
            provider = LocalProvider(
                base_url="http://localhost:11434/v1", model="test"
            )
            chunks = list(provider.analyze_stream("system", "user"))

        self.assertEqual(chunks, ["Non-stream fallback"])


# ---------------------------------------------------------------------------
# LocalProvider._process_stream_chunk
# ---------------------------------------------------------------------------

class TestLocalProviderProcessStreamChunk(unittest.TestCase):
    def test_returns_none_for_no_choices(self) -> None:
        chunk = SimpleNamespace(choices=[])
        self.assertIsNone(LocalProvider._process_stream_chunk(chunk))

    def test_returns_none_for_none_delta(self) -> None:
        chunk = SimpleNamespace(choices=[SimpleNamespace(delta=None)])
        self.assertIsNone(LocalProvider._process_stream_chunk(chunk))

    def test_extracts_thinking_and_answer(self) -> None:
        chunk = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    delta=SimpleNamespace(
                        content="answer",
                        reasoning="thinking",
                    ),
                )
            ]
        )
        result = LocalProvider._process_stream_chunk(chunk)
        self.assertIsNotNone(result)
        thinking, answer = result
        self.assertEqual(thinking, "thinking")
        self.assertEqual(answer, "answer")

    def test_returns_none_for_empty_deltas(self) -> None:
        chunk = SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace())]
        )
        self.assertIsNone(LocalProvider._process_stream_chunk(chunk))

    def test_handles_dict_choice(self) -> None:
        chunk = SimpleNamespace(choices=[{"delta": {"content": "from dict"}}])
        result = LocalProvider._process_stream_chunk(chunk)
        self.assertIsNotNone(result)
        thinking, answer = result
        self.assertEqual(answer, "from dict")
        self.assertEqual(thinking, "")


# ---------------------------------------------------------------------------
# LocalProvider._emit_progress_if_needed
# ---------------------------------------------------------------------------

class TestLocalProviderEmitProgressIfNeeded(unittest.TestCase):
    def test_no_emit_when_no_content(self) -> None:
        callback = MagicMock()
        result = LocalProvider._emit_progress_if_needed(
            progress_callback=callback,
            current_thinking="",
            current_answer="",
            last_emit_at=0.0,
            last_sent_thinking="",
            last_sent_answer="",
        )
        callback.assert_not_called()
        self.assertEqual(result[0], 0.0)

    def test_no_emit_when_unchanged(self) -> None:
        callback = MagicMock()
        result = LocalProvider._emit_progress_if_needed(
            progress_callback=callback,
            current_thinking="same",
            current_answer="same",
            last_emit_at=0.0,
            last_sent_thinking="same",
            last_sent_answer="same",
        )
        callback.assert_not_called()

    def test_emits_when_enough_change(self) -> None:
        callback = MagicMock()
        long_text = "x" * 100
        result = LocalProvider._emit_progress_if_needed(
            progress_callback=callback,
            current_thinking=long_text,
            current_answer="",
            last_emit_at=0.0,
            last_sent_thinking="",
            last_sent_answer="",
        )
        callback.assert_called_once()
        self.assertGreater(result[0], 0.0)
        self.assertEqual(result[1], long_text)

    def test_rate_limits_small_changes(self) -> None:
        callback = MagicMock()
        now = time.monotonic()
        result = LocalProvider._emit_progress_if_needed(
            progress_callback=callback,
            current_thinking="a",
            current_answer="",
            last_emit_at=now,
            last_sent_thinking="",
            last_sent_answer="",
        )
        callback.assert_not_called()
        self.assertEqual(result[0], now)

    def test_handles_callback_exception(self) -> None:
        def bad_callback(payload):
            raise RuntimeError("callback failed")

        long_text = "x" * 100
        result = LocalProvider._emit_progress_if_needed(
            progress_callback=bad_callback,
            current_thinking=long_text,
            current_answer="",
            last_emit_at=0.0,
            last_sent_thinking="",
            last_sent_answer="",
        )
        self.assertGreater(result[0], 0.0)


# ---------------------------------------------------------------------------
# LocalProvider._finalize_stream_response
# ---------------------------------------------------------------------------

class TestLocalProviderFinalizeStreamResponse(unittest.TestCase):
    def test_returns_answer_when_present(self) -> None:
        result = LocalProvider._finalize_stream_response(
            thinking_parts=["thinking"],
            answer_parts=["answer"],
        )
        self.assertEqual(result, "answer")

    def test_returns_thinking_when_no_answer(self) -> None:
        result = LocalProvider._finalize_stream_response(
            thinking_parts=["thinking only"],
            answer_parts=[],
        )
        self.assertEqual(result, "thinking only")

    def test_raises_when_both_empty(self) -> None:
        with self.assertRaises(AIProviderError):
            LocalProvider._finalize_stream_response(
                thinking_parts=[],
                answer_parts=[],
            )

    def test_strips_think_block_from_answer(self) -> None:
        result = LocalProvider._finalize_stream_response(
            thinking_parts=[],
            answer_parts=["<think>reasoning</think>\nFinal."],
        )
        self.assertEqual(result, "Final.")


# ---------------------------------------------------------------------------
# LocalProvider._build_chat_completion_prompt
# ---------------------------------------------------------------------------

class TestLocalProviderBuildChatCompletionPrompt(unittest.TestCase):
    @patch("openai.OpenAI")
    def test_returns_user_prompt_without_attachments(self, mock_openai_cls: MagicMock) -> None:
        provider = LocalProvider(
            base_url="http://localhost:11434/v1", model="test"
        )
        result = provider._build_chat_completion_prompt("user prompt", None)
        self.assertEqual(result, "user prompt")

    @patch("openai.OpenAI")
    def test_inlines_attachments_when_available(self, mock_openai_cls: MagicMock) -> None:
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
                attach_csv_as_file=True,
            )
            result = provider._build_chat_completion_prompt(
                "analyze",
                [{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
            )
            self.assertIn("--- BEGIN ATTACHMENT: data.csv ---", result)

    @patch("openai.OpenAI")
    def test_inlines_attachments_even_when_attach_flag_disabled(self, mock_openai_cls: MagicMock) -> None:
        """When attach_csv_as_file=False, attachments must still be inlined."""
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
                attach_csv_as_file=False,
            )
            result = provider._build_chat_completion_prompt(
                "prompt",
                [{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
            )
            self.assertIn("--- BEGIN ATTACHMENT: data.csv ---", result)
            self.assertIn("a,b", result)


# ---------------------------------------------------------------------------
# create_provider factory
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()
