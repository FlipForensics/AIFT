"""Tests for app.ai_providers module."""

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
from app.ai_providers.base import (
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    RATE_LIMIT_MAX_RETRIES,
    RateLimitState,
    _extract_supported_completion_token_limit,
    _get_rate_limit_state,
    _is_anthropic_streaming_required_error,
    _is_attachment_unsupported_error,
    _is_kimi_model_not_available_error,
    _is_unsupported_parameter_error,
    _normalize_api_key_value,
    _normalize_kimi_model_name,
    _resolve_api_key_candidates,
    _resolve_completion_token_retry_limit,
    _resolve_timeout_seconds,
    _run_with_rate_limit_retries,
    _RATE_LIMIT_STATE,
)
from app.ai_providers.utils import (
    _clean_streamed_answer_text,
    _coerce_openai_text,
    _extract_anthropic_stream_text,
    _extract_openai_delta_text,
    _extract_openai_responses_text,
    _inline_attachment_data_into_prompt,
    _prepare_openai_attachment_upload,
    _strip_leading_reasoning_blocks,
    normalize_attachment_input,
    normalize_attachment_inputs,
    upload_and_request_via_responses_api,
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
# _normalize_api_key_value
# ---------------------------------------------------------------------------

class TestNormalizeApiKeyValue(unittest.TestCase):
    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(_normalize_api_key_value(None), "")

    def test_strips_whitespace(self) -> None:
        self.assertEqual(_normalize_api_key_value("  sk-test  "), "sk-test")

    def test_returns_string_for_non_string(self) -> None:
        self.assertEqual(_normalize_api_key_value(12345), "12345")

    def test_returns_empty_for_empty_string(self) -> None:
        self.assertEqual(_normalize_api_key_value(""), "")

    def test_returns_empty_for_whitespace_only(self) -> None:
        self.assertEqual(_normalize_api_key_value("   "), "")


# ---------------------------------------------------------------------------
# _resolve_api_key
# ---------------------------------------------------------------------------

class TestResolveApiKey(unittest.TestCase):
    def test_returns_config_key_when_present(self) -> None:
        self.assertEqual(_resolve_api_key("sk-config", "DUMMY_VAR"), "sk-config")

    def test_falls_back_to_env_var(self) -> None:
        with patch.dict(os.environ, {"TEST_API_KEY": "sk-env"}):
            self.assertEqual(_resolve_api_key("", "TEST_API_KEY"), "sk-env")

    def test_treats_none_config_key_as_missing(self) -> None:
        with patch.dict(os.environ, {"TEST_API_KEY": "sk-env"}):
            self.assertEqual(_resolve_api_key(None, "TEST_API_KEY"), "sk-env")

    def test_treats_whitespace_config_key_as_missing(self) -> None:
        with patch.dict(os.environ, {"TEST_API_KEY": "sk-env"}):
            self.assertEqual(_resolve_api_key("   ", "TEST_API_KEY"), "sk-env")

    def test_strips_env_var_value(self) -> None:
        with patch.dict(os.environ, {"TEST_API_KEY": "  sk-env  "}):
            self.assertEqual(_resolve_api_key("", "TEST_API_KEY"), "sk-env")

    def test_returns_empty_when_neither_set(self) -> None:
        env = os.environ.copy()
        env.pop("MISSING_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(_resolve_api_key("", "MISSING_KEY"), "")


# ---------------------------------------------------------------------------
# _resolve_api_key_candidates
# ---------------------------------------------------------------------------

class TestResolveApiKeyCandidates(unittest.TestCase):
    def test_returns_config_key_when_present(self) -> None:
        self.assertEqual(
            _resolve_api_key_candidates("sk-config", ("VAR1", "VAR2")),
            "sk-config",
        )

    def test_falls_back_to_first_env_var(self) -> None:
        with patch.dict(os.environ, {"VAR1": "sk-var1"}):
            self.assertEqual(
                _resolve_api_key_candidates("", ("VAR1", "VAR2")),
                "sk-var1",
            )

    def test_falls_back_to_second_env_var(self) -> None:
        env = os.environ.copy()
        env.pop("VAR1", None)
        env["VAR2"] = "sk-var2"
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                _resolve_api_key_candidates("", ("VAR1", "VAR2")),
                "sk-var2",
            )

    def test_returns_empty_when_nothing_found(self) -> None:
        env = os.environ.copy()
        env.pop("VAR1", None)
        env.pop("VAR2", None)
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                _resolve_api_key_candidates("", ("VAR1", "VAR2")),
                "",
            )

    def test_prefers_config_over_env(self) -> None:
        with patch.dict(os.environ, {"VAR1": "sk-env"}):
            self.assertEqual(
                _resolve_api_key_candidates("sk-config", ("VAR1",)),
                "sk-config",
            )


# ---------------------------------------------------------------------------
# _resolve_timeout_seconds
# ---------------------------------------------------------------------------

class TestResolveTimeoutSeconds(unittest.TestCase):
    def test_returns_valid_float(self) -> None:
        self.assertEqual(_resolve_timeout_seconds(300, 600.0), 300.0)

    def test_returns_default_for_none(self) -> None:
        self.assertEqual(_resolve_timeout_seconds(None, 600.0), 600.0)

    def test_returns_default_for_non_numeric_string(self) -> None:
        self.assertEqual(_resolve_timeout_seconds("abc", 600.0), 600.0)

    def test_returns_default_for_zero(self) -> None:
        self.assertEqual(_resolve_timeout_seconds(0, 600.0), 600.0)

    def test_returns_default_for_negative(self) -> None:
        self.assertEqual(_resolve_timeout_seconds(-10, 600.0), 600.0)

    def test_accepts_string_numeric(self) -> None:
        self.assertEqual(_resolve_timeout_seconds("1200", 600.0), 1200.0)


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

    def test_returns_none_for_plain_exception(self) -> None:
        error = Exception("no headers here")
        self.assertIsNone(_extract_retry_after_seconds(error))

    def test_returns_none_when_header_value_is_none(self) -> None:
        error = SimpleNamespace(
            response=SimpleNamespace(headers={"other-header": "val"}),
        )
        self.assertIsNone(_extract_retry_after_seconds(error))


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

    def test_code_attribute_not_string(self) -> None:
        error = Exception("bad request")
        error.code = 400
        self.assertFalse(_is_context_length_error(error))

    def test_detects_input_is_too_long(self) -> None:
        error = Exception("input is too long for this model")
        self.assertTrue(_is_context_length_error(error))

    def test_detects_context_window(self) -> None:
        error = Exception("exceeds the context window")
        self.assertTrue(_is_context_length_error(error))

    def test_detects_token_limit(self) -> None:
        error = Exception("exceeded the token limit")
        self.assertTrue(_is_context_length_error(error))


# ---------------------------------------------------------------------------
# _is_attachment_unsupported_error
# ---------------------------------------------------------------------------

class TestIsAttachmentUnsupportedError(unittest.TestCase):
    def test_detects_404(self) -> None:
        error = Exception("404 page not found")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_not_found(self) -> None:
        error = Exception("endpoint not found")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_unsupported(self) -> None:
        error = Exception("unsupported feature")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_does_not_support(self) -> None:
        error = Exception("does not support file uploads")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_csv_file_type_rejection(self) -> None:
        error = Exception("Expected context stuffing file type to be a supported format but got .csv.")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_false_for_unrelated(self) -> None:
        error = Exception("rate limit exceeded")
        self.assertFalse(_is_attachment_unsupported_error(error))

    def test_detects_unrecognized_request_url(self) -> None:
        error = Exception("unrecognized request url")
        self.assertTrue(_is_attachment_unsupported_error(error))


# ---------------------------------------------------------------------------
# _is_anthropic_streaming_required_error
# ---------------------------------------------------------------------------

class TestIsAnthropicStreamingRequiredError(unittest.TestCase):
    def test_detects_streaming_required_message(self) -> None:
        error = ValueError(
            "Streaming is required for operations that may take longer than 10 minutes."
        )
        self.assertTrue(_is_anthropic_streaming_required_error(error))

    def test_false_for_unrelated_value_error(self) -> None:
        error = ValueError("invalid argument")
        self.assertFalse(_is_anthropic_streaming_required_error(error))

    def test_detects_partial_streaming_required_with_10_minutes(self) -> None:
        error = ValueError("streaming is required because 10 minutes limit")
        self.assertTrue(_is_anthropic_streaming_required_error(error))

    def test_false_when_streaming_required_but_no_10_minutes(self) -> None:
        error = ValueError("streaming is required for large outputs")
        self.assertFalse(_is_anthropic_streaming_required_error(error))


# ---------------------------------------------------------------------------
# _is_unsupported_parameter_error
# ---------------------------------------------------------------------------

class TestIsUnsupportedParameterError(unittest.TestCase):
    def test_detects_from_param_attribute(self) -> None:
        error = Exception("bad request")
        error.param = "max_completion_tokens"
        self.assertTrue(_is_unsupported_parameter_error(error, "max_completion_tokens"))

    def test_false_for_different_param(self) -> None:
        error = Exception("bad request")
        error.param = "temperature"
        self.assertFalse(_is_unsupported_parameter_error(error, "max_completion_tokens"))

    def test_detects_from_body_dict_param(self) -> None:
        error = Exception("bad request")
        error.body = {"error": {"param": "max_completion_tokens", "message": "unsupported"}}
        self.assertTrue(_is_unsupported_parameter_error(error, "max_completion_tokens"))

    def test_detects_from_body_message_unsupported_parameter(self) -> None:
        error = Exception("bad request")
        error.body = {"error": {"message": "Unsupported parameter: 'max_completion_tokens'."}}
        self.assertTrue(_is_unsupported_parameter_error(error, "max_completion_tokens"))

    def test_detects_from_error_message(self) -> None:
        error = Exception("Unsupported parameter: max_completion_tokens")
        self.assertTrue(_is_unsupported_parameter_error(error, "max_completion_tokens"))

    def test_false_for_empty_parameter_name(self) -> None:
        error = Exception("Unsupported parameter: max_completion_tokens")
        self.assertFalse(_is_unsupported_parameter_error(error, ""))

    def test_false_for_none_parameter_name(self) -> None:
        error = Exception("Unsupported parameter: max_completion_tokens")
        self.assertFalse(_is_unsupported_parameter_error(error, None))

    def test_detects_from_body_string_representation(self) -> None:
        error = Exception("bad request")
        error.body = {"message": "Unsupported parameter: max_tokens is not allowed"}
        self.assertTrue(_is_unsupported_parameter_error(error, "max_tokens"))


# ---------------------------------------------------------------------------
# _extract_supported_completion_token_limit
# ---------------------------------------------------------------------------

class TestExtractSupportedCompletionTokenLimit(unittest.TestCase):
    def test_extracts_from_supports_at_most_pattern(self) -> None:
        error = Exception(
            "This model supports at most 128000 completion tokens"
        )
        self.assertEqual(_extract_supported_completion_token_limit(error), 128000)

    def test_extracts_from_max_tokens_upper_bound_pattern(self) -> None:
        error = Exception("max_tokens: 256000 > 128000")
        self.assertEqual(_extract_supported_completion_token_limit(error), 128000)

    def test_returns_none_when_no_match(self) -> None:
        error = Exception("generic error")
        self.assertIsNone(_extract_supported_completion_token_limit(error))

    def test_extracts_from_body_dict_message(self) -> None:
        error = Exception("bad request")
        error.body = {
            "error": {
                "message": "This model supports at most 65536 completion tokens"
            }
        }
        self.assertEqual(_extract_supported_completion_token_limit(error), 65536)

    def test_extracts_from_body_string(self) -> None:
        error = Exception("bad request")
        error.body = {"message": "supports at most 4096 tokens"}
        self.assertEqual(_extract_supported_completion_token_limit(error), 4096)


# ---------------------------------------------------------------------------
# _resolve_completion_token_retry_limit
# ---------------------------------------------------------------------------

class TestResolveCompletionTokenRetryLimit(unittest.TestCase):
    def test_returns_reduced_limit(self) -> None:
        error = Exception("supports at most 128000 completion tokens")
        result = _resolve_completion_token_retry_limit(error, 256000)
        self.assertEqual(result, 128000)

    def test_returns_none_when_limit_ge_requested(self) -> None:
        error = Exception("supports at most 256000 completion tokens")
        result = _resolve_completion_token_retry_limit(error, 128000)
        self.assertIsNone(result)

    def test_returns_none_when_no_limit_found(self) -> None:
        error = Exception("generic error")
        result = _resolve_completion_token_retry_limit(error, 256000)
        self.assertIsNone(result)

    def test_returns_none_for_zero_requested(self) -> None:
        error = Exception("supports at most 128000 completion tokens")
        result = _resolve_completion_token_retry_limit(error, 0)
        self.assertIsNone(result)

    def test_returns_none_for_negative_requested(self) -> None:
        error = Exception("supports at most 128000 completion tokens")
        result = _resolve_completion_token_retry_limit(error, -1)
        self.assertIsNone(result)


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

    def test_returns_default_for_empty(self) -> None:
        result = _normalize_openai_compatible_base_url("", "http://default/v1")
        self.assertEqual(result, "http://default/v1")

    def test_returns_default_for_none(self) -> None:
        result = _normalize_openai_compatible_base_url(None, "http://default/v1")
        self.assertEqual(result, "http://default/v1")

    def test_strips_trailing_slash_on_custom_path(self) -> None:
        result = _normalize_openai_compatible_base_url(
            "http://localhost:8080/api/",
            "http://default/v1",
        )
        self.assertEqual(result, "http://localhost:8080/api")

    def test_adds_v1_for_bare_url(self) -> None:
        result = _normalize_openai_compatible_base_url(
            "http://localhost:11434",
            "http://default/v1",
        )
        self.assertEqual(result, "http://localhost:11434/v1")

    def test_returns_raw_for_no_scheme(self) -> None:
        result = _normalize_openai_compatible_base_url(
            "localhost:11434/v1",
            "http://default/v1",
        )
        self.assertEqual(result, "localhost:11434/v1")


# ---------------------------------------------------------------------------
# _normalize_kimi_model_name
# ---------------------------------------------------------------------------

class TestNormalizeKimiModelName(unittest.TestCase):
    def test_maps_deprecated_alias(self) -> None:
        self.assertEqual(_normalize_kimi_model_name("kimi-v2.5"), DEFAULT_KIMI_MODEL)

    def test_returns_default_for_empty(self) -> None:
        self.assertEqual(_normalize_kimi_model_name(""), DEFAULT_KIMI_MODEL)

    def test_returns_default_for_none(self) -> None:
        self.assertEqual(_normalize_kimi_model_name(None), DEFAULT_KIMI_MODEL)

    def test_passes_through_unknown_model(self) -> None:
        self.assertEqual(_normalize_kimi_model_name("custom-model"), "custom-model")


# ---------------------------------------------------------------------------
# _is_kimi_model_not_available_error
# ---------------------------------------------------------------------------

class TestIsKimiModelNotAvailableError(unittest.TestCase):
    def test_detects_model_not_found(self) -> None:
        error = Exception("model not found: kimi-custom")
        self.assertTrue(_is_kimi_model_not_available_error(error))

    def test_detects_not_found_the_model(self) -> None:
        error = Exception("not found the model requested")
        self.assertTrue(_is_kimi_model_not_available_error(error))

    def test_detects_from_body_dict(self) -> None:
        error = Exception("error")
        error.body = {"error": {"message": "model not found"}}
        self.assertTrue(_is_kimi_model_not_available_error(error))

    def test_false_for_unrelated(self) -> None:
        error = Exception("rate limit exceeded")
        self.assertFalse(_is_kimi_model_not_available_error(error))

    def test_false_when_model_not_in_message(self) -> None:
        error = Exception("not found")
        self.assertFalse(_is_kimi_model_not_available_error(error))

    def test_detects_permission_denied_for_model(self) -> None:
        error = Exception("model: permission denied")
        self.assertTrue(_is_kimi_model_not_available_error(error))


# ---------------------------------------------------------------------------
# RateLimitState and _get_rate_limit_state
# ---------------------------------------------------------------------------

class TestRateLimitState(unittest.TestCase):
    def test_default_values(self) -> None:
        state = RateLimitState()
        self.assertEqual(state.last_request_time, 0.0)
        self.assertEqual(state.backoff_duration, 0.0)
        self.assertEqual(state.consecutive_error_count, 0)

    def test_get_rate_limit_state_creates_new(self) -> None:
        name = f"test-provider-{id(self)}"
        _RATE_LIMIT_STATE.pop(name, None)
        state = _get_rate_limit_state(name)
        self.assertIsInstance(state, RateLimitState)
        _RATE_LIMIT_STATE.pop(name, None)

    def test_get_rate_limit_state_returns_same(self) -> None:
        name = f"test-provider-same-{id(self)}"
        _RATE_LIMIT_STATE.pop(name, None)
        state1 = _get_rate_limit_state(name)
        state2 = _get_rate_limit_state(name)
        self.assertIs(state1, state2)
        _RATE_LIMIT_STATE.pop(name, None)


# ---------------------------------------------------------------------------
# _run_with_rate_limit_retries
# ---------------------------------------------------------------------------

class TestRunWithRateLimitRetries(unittest.TestCase):
    def setUp(self) -> None:
        self.provider_name = f"test-rl-{id(self)}"
        _RATE_LIMIT_STATE.pop(self.provider_name, None)

    def tearDown(self) -> None:
        _RATE_LIMIT_STATE.pop(self.provider_name, None)

    def test_returns_result_on_success(self) -> None:
        result = _run_with_rate_limit_retries(
            request_fn=lambda: "ok",
            rate_limit_error_type=ValueError,
            provider_name=self.provider_name,
        )
        self.assertEqual(result, "ok")

    @patch("app.ai_providers.base.time.sleep")
    def test_retries_on_rate_limit_error(self, mock_sleep: MagicMock) -> None:
        call_count = 0

        def request_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("rate limited")
            return "ok"

        result = _run_with_rate_limit_retries(
            request_fn=request_fn,
            rate_limit_error_type=ValueError,
            provider_name=self.provider_name,
        )
        self.assertEqual(result, "ok")
        self.assertEqual(call_count, 2)
        mock_sleep.assert_called()

    @patch("app.ai_providers.base.time.sleep")
    def test_raises_after_max_retries(self, mock_sleep: MagicMock) -> None:
        def request_fn():
            raise ValueError("rate limited")

        with self.assertRaises(AIProviderError) as ctx:
            _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=ValueError,
                provider_name=self.provider_name,
            )
        self.assertIn("rate limit exceeded", str(ctx.exception))

    def test_does_not_catch_non_rate_limit_errors(self) -> None:
        def request_fn():
            raise TypeError("not rate limited")

        with self.assertRaises(TypeError):
            _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=ValueError,
                provider_name=self.provider_name,
            )

    @patch("app.ai_providers.base.time.sleep")
    def test_uses_retry_after_header_when_available(self, mock_sleep: MagicMock) -> None:
        call_count = 0

        def request_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                error = ValueError("rate limited")
                error.response = SimpleNamespace(headers={"retry-after": "5.0"})
                raise error
            return "ok"

        result = _run_with_rate_limit_retries(
            request_fn=request_fn,
            rate_limit_error_type=ValueError,
            provider_name=self.provider_name,
        )
        self.assertEqual(result, "ok")
        mock_sleep.assert_any_call(5.0)

    @patch("app.ai_providers.base.time.sleep")
    def test_resets_state_on_success(self, mock_sleep: MagicMock) -> None:
        call_count = 0

        def request_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("rate limited")
            return "ok"

        _run_with_rate_limit_retries(
            request_fn=request_fn,
            rate_limit_error_type=ValueError,
            provider_name=self.provider_name,
        )
        state = _get_rate_limit_state(self.provider_name)
        self.assertEqual(state.backoff_duration, 0.0)
        self.assertEqual(state.consecutive_error_count, 0)


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

    def test_returns_empty_for_empty_content_list(self) -> None:
        resp = SimpleNamespace(content=[])
        self.assertEqual(_extract_anthropic_text(resp), "")

    def test_returns_empty_when_no_content_attr(self) -> None:
        resp = SimpleNamespace()
        self.assertEqual(_extract_anthropic_text(resp), "")


# ---------------------------------------------------------------------------
# _extract_anthropic_stream_text
# ---------------------------------------------------------------------------

class TestExtractAnthropicStreamText(unittest.TestCase):
    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(_extract_anthropic_stream_text(None), "")

    def test_extracts_from_content_block_delta(self) -> None:
        event = SimpleNamespace(
            type="content_block_delta",
            delta=SimpleNamespace(text="chunk"),
        )
        self.assertEqual(_extract_anthropic_stream_text(event), "chunk")

    def test_extracts_from_content_block_start(self) -> None:
        event = SimpleNamespace(
            type="content_block_start",
            content_block=SimpleNamespace(text="start text"),
        )
        self.assertEqual(_extract_anthropic_stream_text(event), "start text")

    def test_extracts_from_generic_delta(self) -> None:
        event = SimpleNamespace(
            type="other_type",
            delta=SimpleNamespace(text="generic"),
        )
        self.assertEqual(_extract_anthropic_stream_text(event), "generic")

    def test_returns_empty_for_no_text(self) -> None:
        event = SimpleNamespace(type="message_stop")
        self.assertEqual(_extract_anthropic_stream_text(event), "")

    def test_handles_dict_event_content_block_delta(self) -> None:
        event = {"type": "content_block_delta", "delta": {"text": "dict chunk"}}
        self.assertEqual(_extract_anthropic_stream_text(event), "dict chunk")

    def test_handles_dict_event_content_block_start(self) -> None:
        event = {"type": "content_block_start", "content_block": {"text": "dict start"}}
        self.assertEqual(_extract_anthropic_stream_text(event), "dict start")

    def test_handles_dict_event_generic_delta(self) -> None:
        event = {"type": "other", "delta": {"text": "dict generic"}}
        self.assertEqual(_extract_anthropic_stream_text(event), "dict generic")


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

    def test_list_content_with_content_key(self) -> None:
        message = SimpleNamespace(content=[{"content": "from content key"}])
        choice = SimpleNamespace(message=message)
        resp = SimpleNamespace(choices=[choice])
        self.assertEqual(_extract_openai_text(resp), "from content key")


# ---------------------------------------------------------------------------
# _coerce_openai_text
# ---------------------------------------------------------------------------

class TestCoerceOpenAIText(unittest.TestCase):
    def test_returns_string_as_is(self) -> None:
        self.assertEqual(_coerce_openai_text("hello"), "hello")

    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(_coerce_openai_text(None), "")

    def test_returns_empty_for_int(self) -> None:
        self.assertEqual(_coerce_openai_text(42), "")

    def test_handles_list_of_strings(self) -> None:
        self.assertEqual(_coerce_openai_text(["a", "b"]), "ab")

    def test_handles_list_of_objects_with_text(self) -> None:
        items = [SimpleNamespace(text="x"), SimpleNamespace(text="y")]
        self.assertEqual(_coerce_openai_text(items), "xy")

    def test_handles_list_of_dicts_with_text(self) -> None:
        items = [{"text": "a"}, {"text": "b"}]
        self.assertEqual(_coerce_openai_text(items), "ab")

    def test_handles_list_of_dicts_with_content(self) -> None:
        items = [{"content": "c"}]
        self.assertEqual(_coerce_openai_text(items), "c")

    def test_handles_mixed_list(self) -> None:
        items = ["plain", SimpleNamespace(text="obj"), {"text": "dict"}]
        self.assertEqual(_coerce_openai_text(items), "plainobjdict")

    def test_returns_empty_for_empty_list(self) -> None:
        self.assertEqual(_coerce_openai_text([]), "")


# ---------------------------------------------------------------------------
# _extract_openai_delta_text
# ---------------------------------------------------------------------------

class TestExtractOpenAIDeltaText(unittest.TestCase):
    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(_extract_openai_delta_text(None, ("content",)), "")

    def test_extracts_content_from_object(self) -> None:
        delta = SimpleNamespace(content="hello")
        self.assertEqual(_extract_openai_delta_text(delta, ("content",)), "hello")

    def test_extracts_from_dict(self) -> None:
        delta = {"content": "hello"}
        self.assertEqual(_extract_openai_delta_text(delta, ("content",)), "hello")

    def test_respects_field_priority(self) -> None:
        delta = SimpleNamespace(content="", reasoning_content="reason")
        self.assertEqual(
            _extract_openai_delta_text(delta, ("content", "reasoning_content")),
            "reason",
        )

    def test_returns_empty_when_no_match(self) -> None:
        delta = SimpleNamespace(other="something")
        self.assertEqual(_extract_openai_delta_text(delta, ("content",)), "")


# ---------------------------------------------------------------------------
# _extract_openai_responses_text
# ---------------------------------------------------------------------------

class TestExtractOpenAIResponsesText(unittest.TestCase):
    def test_extracts_from_output_text_attribute(self) -> None:
        resp = SimpleNamespace(output_text="result text")
        self.assertEqual(_extract_openai_responses_text(resp), "result text")

    def test_extracts_from_structured_output(self) -> None:
        block = SimpleNamespace(type="output_text", text="block text")
        item = SimpleNamespace(content=[block])
        resp = SimpleNamespace(output_text=None, output=[item])
        self.assertEqual(_extract_openai_responses_text(resp), "block text")

    def test_returns_empty_for_no_output(self) -> None:
        resp = SimpleNamespace(output_text=None, output=None)
        self.assertEqual(_extract_openai_responses_text(resp), "")

    def test_handles_dict_output_items(self) -> None:
        block = {"type": "text", "text": "dict block"}
        item = {"content": [block]}
        resp = SimpleNamespace(output_text=None, output=[item])
        self.assertEqual(_extract_openai_responses_text(resp), "dict block")

    def test_returns_empty_for_empty_output_list(self) -> None:
        resp = SimpleNamespace(output_text=None, output=[])
        self.assertEqual(_extract_openai_responses_text(resp), "")

    def test_skips_non_text_blocks(self) -> None:
        block1 = SimpleNamespace(type="image", text="ignored")
        block2 = SimpleNamespace(type="output_text", text="kept")
        item = SimpleNamespace(content=[block1, block2])
        resp = SimpleNamespace(output_text=None, output=[item])
        self.assertEqual(_extract_openai_responses_text(resp), "kept")


# ---------------------------------------------------------------------------
# _strip_leading_reasoning_blocks
# ---------------------------------------------------------------------------

class TestStripLeadingReasoningBlocks(unittest.TestCase):
    def test_strips_think_block(self) -> None:
        text = "<think>\nreasoning here\n</think>\n\nFinal answer."
        self.assertEqual(_strip_leading_reasoning_blocks(text), "Final answer.")

    def test_strips_thinking_block(self) -> None:
        text = "<thinking>\nstep by step\n</thinking>\nResult."
        self.assertEqual(_strip_leading_reasoning_blocks(text), "Result.")

    def test_strips_reasoning_block(self) -> None:
        text = "<reasoning>\nlogic\n</reasoning>\nAnswer."
        self.assertEqual(_strip_leading_reasoning_blocks(text), "Answer.")

    def test_returns_empty_for_empty(self) -> None:
        self.assertEqual(_strip_leading_reasoning_blocks(""), "")

    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(_strip_leading_reasoning_blocks(None), "")

    def test_does_not_strip_non_leading(self) -> None:
        text = "Intro <think>reasoning</think> end"
        self.assertEqual(_strip_leading_reasoning_blocks(text), text)

    def test_strips_fenced_code_block(self) -> None:
        text = "```thinking\nreasoning\n```\n\nFinal."
        self.assertEqual(_strip_leading_reasoning_blocks(text), "Final.")


# ---------------------------------------------------------------------------
# _clean_streamed_answer_text
# ---------------------------------------------------------------------------

class TestCleanStreamedAnswerText(unittest.TestCase):
    def test_returns_empty_for_empty_answer(self) -> None:
        self.assertEqual(_clean_streamed_answer_text("", "thinking"), "")

    def test_strips_duplicated_thinking_prefix(self) -> None:
        thinking = "I will reason through this carefully step by step."
        answer = thinking + "\n### Findings\n- Result."
        result = _clean_streamed_answer_text(answer, thinking)
        self.assertEqual(result, "### Findings\n- Result.")

    def test_does_not_strip_short_thinking(self) -> None:
        thinking = "short"
        answer = "short but different content"
        result = _clean_streamed_answer_text(answer, thinking)
        self.assertEqual(result, "short but different content")

    def test_strips_leading_reasoning_blocks(self) -> None:
        answer = "<think>reasoning</think>\nFinal."
        result = _clean_streamed_answer_text(answer, "")
        self.assertEqual(result, "Final.")

    def test_handles_none_values(self) -> None:
        self.assertEqual(_clean_streamed_answer_text(None, None), "")


# ---------------------------------------------------------------------------
# normalize_attachment_input
# ---------------------------------------------------------------------------

class TestNormalizeAttachmentInput(unittest.TestCase):
    def test_returns_none_for_non_mapping(self) -> None:
        self.assertIsNone(normalize_attachment_input("not a dict"))

    def test_returns_none_for_empty_path(self) -> None:
        self.assertIsNone(normalize_attachment_input({"path": ""}))

    def test_returns_none_for_nonexistent_file(self) -> None:
        self.assertIsNone(normalize_attachment_input({"path": "/nonexistent/file.csv"}))

    def test_normalizes_valid_file(self) -> None:
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "test.csv"
            path.write_text("a,b\n1,2\n")
            result = normalize_attachment_input({"path": str(path)})
            self.assertIsNotNone(result)
            self.assertEqual(result["name"], "test.csv")
            self.assertEqual(result["mime_type"], "text/csv")

    def test_uses_provided_name_and_mime(self) -> None:
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "data.csv"
            path.write_text("a,b\n1,2\n")
            result = normalize_attachment_input({
                "path": str(path),
                "name": "custom.csv",
                "mime_type": "application/csv",
            })
            self.assertEqual(result["name"], "custom.csv")
            self.assertEqual(result["mime_type"], "application/csv")

    def test_returns_none_for_directory(self) -> None:
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            self.assertIsNone(normalize_attachment_input({"path": tmp}))


# ---------------------------------------------------------------------------
# normalize_attachment_inputs
# ---------------------------------------------------------------------------

class TestNormalizeAttachmentInputs(unittest.TestCase):
    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(normalize_attachment_inputs(None), [])

    def test_returns_empty_for_empty_list(self) -> None:
        self.assertEqual(normalize_attachment_inputs([]), [])

    def test_filters_invalid_entries(self) -> None:
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "valid.csv"
            path.write_text("a,b\n1,2\n")
            result = normalize_attachment_inputs([
                {"path": str(path)},
                {"path": "/nonexistent/file.csv"},
            ])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["name"], "valid.csv")


# ---------------------------------------------------------------------------
# _prepare_openai_attachment_upload
# ---------------------------------------------------------------------------

class TestPrepareOpenAIAttachmentUpload(unittest.TestCase):
    def test_converts_csv_to_txt(self) -> None:
        attachment = {"path": "/tmp/data.csv", "name": "data.csv", "mime_type": "text/csv"}
        name, mime, converted = _prepare_openai_attachment_upload(attachment)
        self.assertEqual(name, "data.txt")
        self.assertEqual(mime, "text/plain")
        self.assertTrue(converted)

    def test_does_not_convert_non_csv(self) -> None:
        attachment = {"path": "/tmp/data.json", "name": "data.json", "mime_type": "application/json"}
        name, mime, converted = _prepare_openai_attachment_upload(attachment)
        self.assertEqual(name, "data.json")
        self.assertEqual(mime, "application/json")
        self.assertFalse(converted)

    def test_detects_csv_by_mime_type(self) -> None:
        attachment = {"path": "/tmp/data.dat", "name": "data.dat", "mime_type": "application/csv"}
        name, mime, converted = _prepare_openai_attachment_upload(attachment)
        self.assertEqual(name, "data.txt")
        self.assertEqual(mime, "text/plain")
        self.assertTrue(converted)

    def test_detects_csv_by_path_suffix(self) -> None:
        attachment = {"path": "/tmp/data.csv", "name": "data", "mime_type": "text/plain"}
        name, mime, converted = _prepare_openai_attachment_upload(attachment)
        self.assertEqual(name, "data.txt")
        self.assertEqual(mime, "text/plain")
        self.assertTrue(converted)


# ---------------------------------------------------------------------------
# _inline_attachment_data_into_prompt
# ---------------------------------------------------------------------------

class TestInlineAttachmentDataIntoPrompt(unittest.TestCase):
    def test_returns_original_for_none_attachments(self) -> None:
        prompt, inlined = _inline_attachment_data_into_prompt("hello", None)
        self.assertEqual(prompt, "hello")
        self.assertFalse(inlined)

    def test_returns_original_for_empty_attachments(self) -> None:
        prompt, inlined = _inline_attachment_data_into_prompt("hello", [])
        self.assertEqual(prompt, "hello")
        self.assertFalse(inlined)

    def test_inlines_attachment_content(self) -> None:
        with TemporaryDirectory(prefix="aift-test-") as tmp:
            path = Path(tmp) / "test.csv"
            path.write_text("a,b\n1,2\n")
            prompt, inlined = _inline_attachment_data_into_prompt(
                "Analyze this",
                [{"path": str(path), "name": "test.csv", "mime_type": "text/csv"}],
            )
            self.assertTrue(inlined)
            self.assertIn("--- BEGIN ATTACHMENT: test.csv ---", prompt)
            self.assertIn("a,b", prompt)
            self.assertIn("File attachments were unavailable", prompt)

    def test_skips_unreadable_files(self) -> None:
        prompt, inlined = _inline_attachment_data_into_prompt(
            "Analyze this",
            [{"path": "/nonexistent/file.csv", "name": "file.csv", "mime_type": "text/csv"}],
        )
        self.assertEqual(prompt, "Analyze this")
        self.assertFalse(inlined)


# ---------------------------------------------------------------------------
# AIProvider._prepare_csv_attachments
# ---------------------------------------------------------------------------

class TestPrepareCsvAttachments(unittest.TestCase):
    def test_returns_none_when_attach_csv_as_file_is_false(self) -> None:
        provider = MagicMock(spec=AIProvider)
        provider.attach_csv_as_file = False
        result = AIProvider._prepare_csv_attachments(
            provider, [{"path": "/tmp/x.csv"}]
        )
        self.assertIsNone(result)

    def test_returns_none_for_empty_attachments(self) -> None:
        provider = MagicMock(spec=AIProvider)
        provider.attach_csv_as_file = True
        result = AIProvider._prepare_csv_attachments(provider, [])
        self.assertIsNone(result)

    def test_returns_none_for_none_attachments(self) -> None:
        provider = MagicMock(spec=AIProvider)
        provider.attach_csv_as_file = True
        result = AIProvider._prepare_csv_attachments(provider, None)
        self.assertIsNone(result)

    def test_returns_none_when_csv_attachment_supported_is_false(self) -> None:
        provider = MagicMock(spec=AIProvider)
        provider.attach_csv_as_file = True
        provider._csv_attachment_supported = False
        result = AIProvider._prepare_csv_attachments(
            provider, [{"path": "/tmp/x.csv"}]
        )
        self.assertIsNone(result)

    def test_returns_none_when_file_attachments_not_supported(self) -> None:
        provider = MagicMock(spec=AIProvider)
        provider.attach_csv_as_file = True
        provider._csv_attachment_supported = None
        result = AIProvider._prepare_csv_attachments(
            provider, [{"path": "/tmp/x.csv"}], supports_file_attachments=False
        )
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# AIProvider.analyze_with_attachments (default implementation)
# ---------------------------------------------------------------------------

class TestAIProviderDefaultAnalyzeWithAttachments(unittest.TestCase):
    def test_delegates_to_analyze(self) -> None:
        class _ConcreteProvider(AIProvider):
            def analyze(self, system_prompt, user_prompt, max_tokens=DEFAULT_MAX_TOKENS):
                return f"analyzed: {user_prompt}"
            def analyze_stream(self, system_prompt, user_prompt, max_tokens=DEFAULT_MAX_TOKENS):
                yield "chunk"
            def get_model_info(self):
                return {"provider": "test", "model": "test"}

        provider = _ConcreteProvider()
        result = provider.analyze_with_attachments("sys", "user", attachments=[{"path": "/x"}])
        self.assertEqual(result, "analyzed: user")


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
        self.assertEqual(kwargs["max_tokens"], 256000)

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
        self.assertEqual(provider.api_key, "not-needed")

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
        mock_client.responses.create.side_effect = RuntimeError("404 page not found")
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
        self.assertEqual(provider.api_key, "sk-from-env")

    @patch("anthropic.Anthropic")
    def test_env_var_fallback_for_none_claude_key(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "claude", "claude": {"api_key": None}}}
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
    def test_env_var_fallback_for_none_openai_key(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "openai", "openai": {"api_key": None}}}
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

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_none_kimi_key(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "kimi", "kimi": {"api_key": None}}}
        with patch.dict(os.environ, {"MOONSHOT_API_KEY": "sk-from-env"}):
            provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider.api_key, "sk-from-env")

    @patch("openai.OpenAI")
    def test_env_var_fallback_for_kimi_api_key_var(self, _mock: MagicMock) -> None:
        config = {"ai": {"provider": "kimi", "kimi": {"api_key": ""}}}
        env = os.environ.copy()
        env.pop("MOONSHOT_API_KEY", None)
        env["KIMI_API_KEY"] = "sk-kimi-env"
        with patch.dict(os.environ, env, clear=True):
            provider = create_provider(config)
        self.assertIsInstance(provider, KimiProvider)
        self.assertEqual(provider.api_key, "sk-kimi-env")

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
        mock_client.responses.create.side_effect = RuntimeError("404 not found")
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
