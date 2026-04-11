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
    def test_detects_file_not_found(self) -> None:
        error = Exception("file not found on server")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_file_not_found_underscore(self) -> None:
        error = Exception("error: file_not_found")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_attachment_not_found(self) -> None:
        error = Exception("attachment not found")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_unsupported_file(self) -> None:
        error = Exception("unsupported file format")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_detects_attachments_not_supported(self) -> None:
        error = Exception("attachments not supported by this model")
        self.assertTrue(_is_attachment_unsupported_error(error))

    def test_ignores_generic_404(self) -> None:
        error = Exception("404 model not found")
        self.assertFalse(_is_attachment_unsupported_error(error))

    def test_ignores_generic_not_found(self) -> None:
        error = Exception("endpoint not found")
        self.assertFalse(_is_attachment_unsupported_error(error))

    def test_ignores_generic_unsupported(self) -> None:
        error = Exception("unsupported feature")
        self.assertFalse(_is_attachment_unsupported_error(error))

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


if __name__ == "__main__":
    unittest.main()
