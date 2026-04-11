"""Tests for AI provider factory, error passthrough, and attachment fallback.

Covers create_provider factory function, AIProviderError passthrough behavior,
upload_and_request_via_responses_api, and attachment fallback regression tests.
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
    DEFAULT_KIMI_MODEL,
    KimiProvider,
    LocalProvider,
    OpenAIProvider,
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
    def test_creates_local_provider_with_custom_timeout(self, _mock: MagicMock) -> None:
        config = {
            "ai": {
                "provider": "local",
                "local": {
                    "base_url": "http://localhost:11434/v1",
                    "model": "llama3.1:70b",
                    "request_timeout_seconds": 5400,
                },
            }
        }
        provider = create_provider(config)
        self.assertIsInstance(provider, LocalProvider)
        self.assertEqual(provider.request_timeout_seconds, 5400.0)

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
        self.assertEqual(provider._api_key, "sk-from-env")

    @patch("anthropic.Anthropic")
    def test_env_var_fallback_for_none_claude_key(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "claude", "claude": {"api_key": None}}}
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, ClaudeProvider)
        self.assertEqual(provider._api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_openai(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "openai", "openai": {"api_key": ""}}}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertEqual(provider._api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_none_openai_key(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "openai", "openai": {"api_key": None}}}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, OpenAIProvider)
        self.assertEqual(provider._api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_kimi(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "kimi", "kimi": {"api_key": ""}}}
        with patch.dict(os.environ, {"MOONSHOT_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider._api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_none_kimi_key(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "kimi", "kimi": {"api_key": None}}}
        with patch.dict(os.environ, {"MOONSHOT_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider._api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_kimi_api_key_var(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "kimi", "kimi": {"api_key": ""}}}
        env = os.environ.copy()
        env.pop("MOONSHOT_API_KEY", None)
        env["KIMI_API_KEY"] = "sk-kimi-env"
        with patch.dict(os.environ, env, clear=True):
            provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider._api_key, "sk-kimi-env")

    @patch("openai.OpenAI")
    def test_rejects_blank_openai_key_before_client_call(self, mock_openai_cls: MagicMock) -> None:
        config = {"ai": {"provider": "openai", "openai": {"api_key": "   "}}}
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            with self.assertRaises(AIProviderError) as ctx:
                create_provider(config)
        self.assertIn("API key is not configured", str(ctx.exception))
        mock_openai_cls.assert_not_called()

    def test_raises_on_invalid_claude_subsection(self) -> None:
        config = {"ai": {"provider": "claude", "claude": "not a dict"}}
        with self.assertRaises(ValueError) as ctx:
            create_provider(config)
        self.assertIn("ai.claude", str(ctx.exception))

    def test_raises_on_invalid_openai_subsection(self) -> None:
        config = {"ai": {"provider": "openai", "openai": "not a dict"}}
        with self.assertRaises(ValueError) as ctx:
            create_provider(config)
        self.assertIn("ai.openai", str(ctx.exception))

    def test_raises_on_invalid_local_subsection(self) -> None:
        config = {"ai": {"provider": "local", "local": "not a dict"}}
        with self.assertRaises(ValueError) as ctx:
            create_provider(config)
        self.assertIn("ai.local", str(ctx.exception))

    def test_raises_on_invalid_kimi_subsection(self) -> None:
        config = {"ai": {"provider": "kimi", "kimi": "not a dict"}}
        with self.assertRaises(ValueError) as ctx:
            create_provider(config)
        self.assertIn("ai.kimi", str(ctx.exception))

    @patch("anthropic.Anthropic")
    def test_creates_provider_with_empty_ai_section(self, _mock: MagicMock) -> None:
        config: dict = {}
        with self.assertRaises(AIProviderError):
            create_provider(config)


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

    @patch("openai.OpenAI")
    def test_kimi_empty_response_not_double_wrapped(
        self, mock_openai_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[])

        provider = KimiProvider(api_key="sk-test")
        with self.assertRaises(AIProviderError) as ctx:
            provider.analyze("system", "user")
        self.assertIn("empty response", str(ctx.exception))
        self.assertNotIn("Unexpected", str(ctx.exception))


# ---------------------------------------------------------------------------
# upload_and_request_via_responses_api
# ---------------------------------------------------------------------------

class TestUploadAndRequestViaResponsesAPI(unittest.TestCase):
    def test_uploads_files_and_returns_text(self) -> None:
        import openai as openai_module

        mock_client = MagicMock()
        mock_client.files.create.return_value = SimpleNamespace(id="file-001")
        mock_client.responses.create.return_value = SimpleNamespace(output_text="response text")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            result = upload_and_request_via_responses_api(
                client=mock_client,
                openai_module=openai_module,
                model="test-model",
                normalized_attachments=[{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
                system_prompt="sys",
                user_prompt="user",
                max_tokens=1000,
                provider_name="Test",
            )

        self.assertEqual(result, "response text")
        mock_client.files.create.assert_called_once()
        mock_client.responses.create.assert_called_once()
        mock_client.files.delete.assert_called_once_with("file-001")

    def test_raises_on_empty_response(self) -> None:
        import openai as openai_module

        mock_client = MagicMock()
        mock_client.files.create.return_value = SimpleNamespace(id="file-001")
        mock_client.responses.create.return_value = SimpleNamespace(output_text="")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            with self.assertRaises(AIProviderError) as ctx:
                upload_and_request_via_responses_api(
                    client=mock_client,
                    openai_module=openai_module,
                    model="test-model",
                    normalized_attachments=[{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
                    system_prompt="sys",
                    user_prompt="user",
                    max_tokens=1000,
                    provider_name="Test",
                )
            self.assertIn("empty response", str(ctx.exception))

        mock_client.files.delete.assert_called_once_with("file-001")

    def test_raises_when_file_upload_returns_no_id(self) -> None:
        import openai as openai_module

        mock_client = MagicMock()
        mock_client.files.create.return_value = SimpleNamespace(id=None)

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            with self.assertRaises(AIProviderError) as ctx:
                upload_and_request_via_responses_api(
                    client=mock_client,
                    openai_module=openai_module,
                    model="test-model",
                    normalized_attachments=[{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
                    system_prompt="sys",
                    user_prompt="user",
                    max_tokens=1000,
                    provider_name="Test",
                )
            self.assertIn("file id", str(ctx.exception).lower())

    def test_cleans_up_files_on_failure(self) -> None:
        import openai as openai_module

        mock_client = MagicMock()
        mock_client.files.create.return_value = SimpleNamespace(id="file-cleanup")
        mock_client.responses.create.side_effect = RuntimeError("API error")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            with self.assertRaises(RuntimeError):
                upload_and_request_via_responses_api(
                    client=mock_client,
                    openai_module=openai_module,
                    model="test-model",
                    normalized_attachments=[{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
                    system_prompt="sys",
                    user_prompt="user",
                    max_tokens=1000,
                    provider_name="Test",
                )

        mock_client.files.delete.assert_called_once_with("file-cleanup")

    def test_converts_csv_to_txt_when_flag_set(self) -> None:
        import openai as openai_module

        mock_client = MagicMock()
        mock_client.files.create.return_value = SimpleNamespace(id="file-conv")
        mock_client.responses.create.return_value = SimpleNamespace(output_text="converted result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")

            upload_and_request_via_responses_api(
                client=mock_client,
                openai_module=openai_module,
                model="test-model",
                normalized_attachments=[{"path": str(path), "name": "data.csv", "mime_type": "text/csv"}],
                system_prompt="sys",
                user_prompt="user",
                max_tokens=1000,
                provider_name="Test",
                convert_csv_to_txt=True,
            )

        upload_kwargs = mock_client.files.create.call_args.kwargs
        file_tuple = upload_kwargs["file"]
        self.assertEqual(file_tuple[0], "data.txt")
        self.assertEqual(file_tuple[2], "text/plain")


# ---------------------------------------------------------------------------
# Attachment fallback regression tests
# ---------------------------------------------------------------------------


class TestAttachmentFallbackRegression(unittest.TestCase):
    """Regression tests ensuring attachment content is always delivered to the
    model, even when file-attachment mode is disabled or rejected."""

    @patch("anthropic.Anthropic")
    def test_claude_attach_csv_as_file_false_still_inlines(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        """Claude with attach_csv_as_file=False must inline attachment data."""
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _make_anthropic_response("result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "evidence.csv"
            csv_path.write_text("ts,name\n2026-01-15,EntryA\n", encoding="utf-8")

            provider = ClaudeProvider(
                api_key="sk-test", model="claude-sonnet-4-20250514", attach_csv_as_file=False
            )
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "evidence.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "result")
        prompt = mock_client.messages.create.call_args.kwargs["messages"][0]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: evidence.csv ---", prompt)
        self.assertIn("ts,name", prompt)

    @patch("openai.OpenAI")
    def test_openai_attach_csv_as_file_false_still_inlines(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        """OpenAI with attach_csv_as_file=False must inline attachment data."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response("result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "evidence.csv"
            csv_path.write_text("ts,name\n2026-01-15,EntryA\n", encoding="utf-8")

            provider = OpenAIProvider(
                api_key="sk-test", model="gpt-4o", attach_csv_as_file=False
            )
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "evidence.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "result")
        prompt = mock_client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: evidence.csv ---", prompt)
        self.assertIn("ts,name", prompt)

    @patch("openai.OpenAI")
    def test_kimi_attach_csv_as_file_false_still_inlines(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        """Kimi with attach_csv_as_file=False must inline attachment data."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response("result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "evidence.csv"
            csv_path.write_text("ts,name\n2026-01-15,EntryA\n", encoding="utf-8")

            provider = KimiProvider(
                api_key="sk-test", attach_csv_as_file=False
            )
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "evidence.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "result")
        prompt = mock_client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: evidence.csv ---", prompt)
        self.assertIn("ts,name", prompt)

    @patch("openai.OpenAI")
    def test_local_attach_csv_as_file_false_still_inlines(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        """Local with attach_csv_as_file=False must inline attachment data."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = _make_openai_response("result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "evidence.csv"
            csv_path.write_text("ts,name\n2026-01-15,EntryA\n", encoding="utf-8")

            provider = LocalProvider(
                base_url="http://localhost:11434/v1",
                model="test",
                attach_csv_as_file=False,
            )
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "evidence.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "result")
        prompt = mock_client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: evidence.csv ---", prompt)
        self.assertIn("ts,name", prompt)

    @patch("openai.OpenAI")
    def test_openai_upload_rejection_still_inlines(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        """When OpenAI rejects file upload, fallback must inline content."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-x")
        mock_client.responses.create.side_effect = RuntimeError("unsupported file format")
        mock_client.chat.completions.create.return_value = _make_openai_response("fallback result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "data.csv"
            csv_path.write_text("col1,col2\nval1,val2\n", encoding="utf-8")

            provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "data.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "fallback result")
        prompt = mock_client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: data.csv ---", prompt)
        self.assertIn("col1,col2", prompt)

    @patch("anthropic.Anthropic")
    def test_claude_upload_rejection_still_inlines(
        self,
        mock_anthropic_cls: MagicMock,
    ) -> None:
        """When Claude rejects attachment content blocks, fallback must inline."""
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.side_effect = [
            RuntimeError("unsupported document input"),
            _make_anthropic_response("fallback result"),
        ]

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "data.csv"
            csv_path.write_text("col1,col2\nval1,val2\n", encoding="utf-8")

            provider = ClaudeProvider(api_key="sk-test", model="claude-sonnet-4-20250514")
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "data.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "fallback result")
        fallback_prompt = mock_client.messages.create.call_args_list[1].kwargs["messages"][0]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: data.csv ---", fallback_prompt)
        self.assertIn("col1,col2", fallback_prompt)

    @patch("openai.OpenAI")
    def test_kimi_upload_rejection_still_inlines(
        self,
        mock_openai_cls: MagicMock,
    ) -> None:
        """When Kimi rejects file upload, fallback must inline content."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.files.create.return_value = SimpleNamespace(id="file-x")
        mock_client.responses.create.side_effect = RuntimeError("unrecognized request url /responses")
        mock_client.chat.completions.create.return_value = _make_openai_response("fallback result")

        with TemporaryDirectory(prefix="aift-test-") as tmp:
            csv_path = Path(tmp) / "data.csv"
            csv_path.write_text("col1,col2\nval1,val2\n", encoding="utf-8")

            provider = KimiProvider(api_key="sk-test")
            result = provider.analyze_with_attachments(
                "system",
                "user",
                attachments=[{"path": str(csv_path), "name": "data.csv", "mime_type": "text/csv"}],
            )

        self.assertEqual(result, "fallback result")
        prompt = mock_client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertIn("--- BEGIN ATTACHMENT: data.csv ---", prompt)
        self.assertIn("col1,col2", prompt)


if __name__ == "__main__":
    unittest.main()
