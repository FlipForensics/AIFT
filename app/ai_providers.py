"""AI provider abstractions for Claude, OpenAI, Kimi, and local models."""

from __future__ import annotations

import base64
import logging
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOKENS = 256000
RATE_LIMIT_MAX_RETRIES = 3
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
DEFAULT_KIMI_BASE_URL = "https://api.moonshot.ai/v1"
DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"
DEFAULT_OPENAI_MODEL = "gpt-5.2"
DEFAULT_KIMI_MODEL = "kimi-k2-turbo-preview"
DEFAULT_KIMI_FILE_UPLOAD_PURPOSE = "file-extract"
DEFAULT_LOCAL_MODEL = "llama3.1:70b"

_KIMI_MODEL_ALIASES = {
    "kimi-v2.5": DEFAULT_KIMI_MODEL,
}

_CONTEXT_LENGTH_PATTERNS = (
    "context length",
    "context window",
    "context_length_exceeded",
    "maximum context",
    "too many tokens",
    "token limit",
    "prompt is too long",
    "input is too long",
)

_KIMI_MODEL_NOT_AVAILABLE_PATTERNS = (
    "not found the model",
    "model not found",
    "resource_not_found_error",
    "permission denied",
    "unknown model",
)

_LEADING_REASONING_BLOCK_RE = re.compile(
    r"^\s*(?:"
    r"(?:<\s*(?:think|thinking|reasoning)\b[^>]*>.*?<\s*/\s*(?:think|thinking|reasoning)\s*>\s*)"
    r"|(?:```(?:think|thinking|reasoning)[^\n]*\n.*?```\s*)"
    r")+",
    flags=re.IGNORECASE | re.DOTALL,
)

_SUPPORTED_COMPLETION_TOKEN_LIMIT_RE = re.compile(
    r"supports\s+at\s+most\s+(?P<limit>\d+)\s+(?:completion\s+)?tokens",
    flags=re.IGNORECASE,
)
_MAX_TOKENS_UPPER_BOUND_RE = re.compile(
    r"max[_\s]?tokens?\s*:\s*\d+\s*>\s*(?P<limit>\d+)",
    flags=re.IGNORECASE,
)


class AIProviderError(RuntimeError):
    """Raised when an AI provider request fails with a user-facing message."""


class AIProvider(ABC):
    """Abstract interface implemented by all configured AI providers."""

    @abstractmethod
    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to the provider and return the generated text."""

    @abstractmethod
    def get_model_info(self) -> dict[str, str]:
        """Return provider and model metadata for reporting."""

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional attachments (default behavior ignores attachments)."""
        return self.analyze(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
        )


def _resolve_api_key(config_key: str, env_var: str) -> str:
    """Return the API key from config, falling back to an environment variable."""
    if config_key:
        return config_key
    return os.environ.get(env_var, "")


def _resolve_api_key_candidates(config_key: str, env_vars: tuple[str, ...]) -> str:
    """Return API key from config, falling back across multiple environment variables."""
    if config_key:
        return config_key

    for env_var in env_vars:
        value = os.environ.get(env_var, "")
        if value:
            return value
    return ""


def _extract_retry_after_seconds(error: Exception) -> float | None:
    """Read Retry-After hints from API error responses when present."""
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        headers = getattr(error, "headers", None)
    if headers is None:
        return None

    retry_after_value = headers.get("retry-after") or headers.get("Retry-After")
    if retry_after_value is None:
        return None

    try:
        retry_after = float(retry_after_value)
    except (TypeError, ValueError):
        return None

    return max(0.0, retry_after)


def _is_context_length_error(error: Exception) -> bool:
    """Best-effort detection for context/token-length failures."""
    message = str(error).lower()
    if any(pattern in message for pattern in _CONTEXT_LENGTH_PATTERNS):
        return True

    code = getattr(error, "code", None)
    if isinstance(code, str) and "context" in code.lower():
        return True

    body = getattr(error, "body", None)
    if isinstance(body, dict):
        body_text = str(body).lower()
        if any(pattern in body_text for pattern in _CONTEXT_LENGTH_PATTERNS):
            return True

    return False


def _normalize_openai_compatible_base_url(base_url: str, default_base_url: str) -> str:
    """Normalize OpenAI-compatible base URLs.

    OpenAI-compatible SDK clients expect the versioned API prefix (commonly
    `/v1`). Ollama users often provide `http://localhost:11434/`; in that
    case we normalize to `http://localhost:11434/v1`.
    """
    raw = str(base_url or "").strip()
    if not raw:
        return default_base_url

    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw.rstrip("/")

    normalized_path = parsed.path.rstrip("/")
    if normalized_path in ("", "/"):
        normalized_path = "/v1"

    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, parsed.fragment))


def _normalize_kimi_model_name(model: str) -> str:
    """Normalize Kimi model names and map deprecated aliases."""
    raw = str(model or "").strip()
    if not raw:
        return DEFAULT_KIMI_MODEL

    mapped = _KIMI_MODEL_ALIASES.get(raw.lower())
    if mapped:
        logger.warning("Kimi model '%s' is deprecated; using '%s'.", raw, mapped)
        return mapped
    return raw


def _is_kimi_model_not_available_error(error: Exception) -> bool:
    """Detect model-not-found or model-permission failures from Kimi responses."""
    message = str(error).lower()
    if "model" in message and any(pattern in message for pattern in _KIMI_MODEL_NOT_AVAILABLE_PATTERNS):
        return True

    body = getattr(error, "body", None)
    if isinstance(body, dict):
        body_text = str(body).lower()
        if "model" in body_text and any(pattern in body_text for pattern in _KIMI_MODEL_NOT_AVAILABLE_PATTERNS):
            return True

    return False


def _extract_anthropic_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return ""

    chunks: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            chunks.append(text)
            continue

        if isinstance(block, dict):
            block_text = block.get("text")
            if isinstance(block_text, str):
                chunks.append(block_text)

    return "".join(chunks).strip()


def _extract_openai_text(response: Any) -> str:
    choices = getattr(response, "choices", None)
    if not choices:
        return ""

    first_choice = choices[0]
    message = getattr(first_choice, "message", None)
    if message is None and isinstance(first_choice, dict):
        message = first_choice.get("message")

    if message is None:
        return ""

    content = getattr(message, "content", None)
    if content is None and isinstance(message, dict):
        content = message.get("content")

    if isinstance(content, str):
        stripped_content = content.strip()
        if stripped_content:
            return stripped_content

    if isinstance(content, list):
        parts: list[str] = []
        for chunk in content:
            text = getattr(chunk, "text", None)
            if isinstance(text, str):
                parts.append(text)
                continue

            if isinstance(chunk, dict):
                chunk_text = chunk.get("text")
                if isinstance(chunk_text, str):
                    parts.append(chunk_text)
                    continue
                chunk_content = chunk.get("content")
                if isinstance(chunk_content, str):
                    parts.append(chunk_content)
        joined = "".join(parts).strip()
        if joined:
            return joined

    # Reasoning-capable local models can return empty message.content while
    # putting output in alternate fields.
    for field_name in ("reasoning_content", "reasoning", "refusal"):
        field_value = getattr(message, field_name, None)
        if field_value is None and isinstance(message, dict):
            field_value = message.get(field_name)
        if isinstance(field_value, str):
            stripped_value = field_value.strip()
            if stripped_value:
                return stripped_value
        if isinstance(field_value, list):
            list_parts: list[str] = []
            for item in field_value:
                if isinstance(item, str):
                    list_parts.append(item)
                    continue
                item_text = getattr(item, "text", None)
                if isinstance(item_text, str):
                    list_parts.append(item_text)
                    continue
                if isinstance(item, dict):
                    dict_text = item.get("text")
                    if isinstance(dict_text, str):
                        list_parts.append(dict_text)
            joined_list = "".join(list_parts).strip()
            if joined_list:
                return joined_list

    return ""


def _extract_openai_delta_text(delta: Any, field_names: tuple[str, ...]) -> str:
    """Extract streaming delta text for one of the requested fields."""
    if delta is None:
        return ""

    for field_name in field_names:
        value = getattr(delta, field_name, None)
        if value is None and isinstance(delta, dict):
            value = delta.get(field_name)
        text = _coerce_openai_text(value)
        if text:
            return text
    return ""


def _coerce_openai_text(value: Any) -> str:
    """Normalize OpenAI-compatible response text payloads into plain strings."""
    if isinstance(value, str):
        return value

    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
                continue
            item_text = getattr(item, "text", None)
            if isinstance(item_text, str):
                parts.append(item_text)
                continue
            if isinstance(item, dict):
                dict_text = item.get("text")
                if isinstance(dict_text, str):
                    parts.append(dict_text)
                    continue
                dict_content = item.get("content")
                if isinstance(dict_content, str):
                    parts.append(dict_content)
        return "".join(parts)

    return ""


def _extract_openai_responses_text(response: Any) -> str:
    """Extract output text from OpenAI Responses API payloads."""
    output_text = getattr(response, "output_text", None)
    text = _coerce_openai_text(output_text).strip()
    if text:
        return text

    output_items = getattr(response, "output", None)
    if output_items is None and isinstance(response, dict):
        output_items = response.get("output")
    if not isinstance(output_items, list):
        return ""

    parts: list[str] = []
    for item in output_items:
        content = getattr(item, "content", None)
        if content is None and isinstance(item, dict):
            content = item.get("content")
        if not isinstance(content, list):
            continue

        for block in content:
            block_type = getattr(block, "type", None)
            if block_type is None and isinstance(block, dict):
                block_type = block.get("type")
            if str(block_type) not in {"output_text", "text"}:
                continue

            block_text = getattr(block, "text", None)
            if block_text is None and isinstance(block, dict):
                block_text = block.get("text")
            normalized = _coerce_openai_text(block_text)
            if normalized:
                parts.append(normalized)

    return "".join(parts).strip()


def _strip_leading_reasoning_blocks(text: str) -> str:
    """Remove leading model-thinking blocks from OpenAI-compatible output."""
    value = str(text or "").strip()
    if not value:
        return ""
    return _LEADING_REASONING_BLOCK_RE.sub("", value, count=1).strip()


def _clean_streamed_answer_text(answer_text: str, thinking_text: str) -> str:
    """Drop duplicated streamed thinking text from the final answer channel."""
    answer = str(answer_text or "").strip()
    if not answer:
        return ""

    thinking = str(thinking_text or "").strip()
    if thinking and len(thinking) >= 24 and answer.startswith(thinking):
        answer = answer[len(thinking) :].lstrip()

    return _strip_leading_reasoning_blocks(answer)


def _is_attachment_unsupported_error(error: Exception) -> bool:
    """Detect API errors that indicate attachment/file APIs are unsupported."""
    message = str(error).lower()
    unsupported_markers = (
        "404",
        "not found",
        "unsupported",
        "does not support",
        "input_file",
        "/responses",
        "/files",
        "unrecognized request url",
        "unknown field",
        "supported format",
        "context stuffing file type",
        "but got .csv",
    )
    return any(marker in message for marker in unsupported_markers)


def _is_anthropic_streaming_required_error(error: Exception) -> bool:
    """Detect Anthropic SDK non-streaming timeout guardrails for long requests."""
    message = str(error).lower()
    if "streaming is required for operations that may take longer than 10 minutes" in message:
        return True
    return "streaming is required" in message and "10 minutes" in message


def _is_unsupported_parameter_error(error: Exception, parameter_name: str) -> bool:
    """Detect API errors that indicate a specific parameter is unsupported."""
    parameter = str(parameter_name or "").strip().lower()
    if not parameter:
        return False

    param = getattr(error, "param", None)
    if isinstance(param, str) and param.lower() == parameter:
        return True

    body = getattr(error, "body", None)
    if isinstance(body, dict):
        error_payload = body.get("error", body)
        if isinstance(error_payload, Mapping):
            body_param = error_payload.get("param")
            if isinstance(body_param, str) and body_param.lower() == parameter:
                return True
            body_message = error_payload.get("message")
            if isinstance(body_message, str):
                lowered_message = body_message.lower()
                if parameter in lowered_message and "unsupported parameter" in lowered_message:
                    return True

        lowered_body = str(body).lower()
        if parameter in lowered_body and "unsupported parameter" in lowered_body:
            return True

    lowered_message = str(error).lower()
    return parameter in lowered_message and "unsupported parameter" in lowered_message


def _extract_supported_completion_token_limit(error: Exception) -> int | None:
    """Extract a provider-declared completion token cap from an API error."""
    candidate_messages: list[str] = []
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        error_payload = body.get("error", body)
        if isinstance(error_payload, Mapping):
            body_message = error_payload.get("message")
            if isinstance(body_message, str):
                candidate_messages.append(body_message)
        candidate_messages.append(str(body))
    candidate_messages.append(str(error))

    patterns = (
        _SUPPORTED_COMPLETION_TOKEN_LIMIT_RE,
        _MAX_TOKENS_UPPER_BOUND_RE,
    )
    for message in candidate_messages:
        for pattern in patterns:
            match = pattern.search(message)
            if not match:
                continue
            try:
                limit = int(match.group("limit"))
            except (TypeError, ValueError):
                continue
            if limit > 0:
                return limit
    return None


def _resolve_completion_token_retry_limit(
    error: Exception,
    requested_tokens: int,
) -> int | None:
    """Return a reduced token count when the API reports the model maximum."""
    if requested_tokens <= 0:
        return None
    supported_limit = _extract_supported_completion_token_limit(error)
    if supported_limit is None or supported_limit >= requested_tokens:
        return None
    return supported_limit


def _prepare_openai_attachment_upload(attachment: Mapping[str, str]) -> tuple[str, str, bool]:
    """Normalize OpenAI attachment upload metadata.

    Some OpenAI Responses API models reject `.csv` file extensions for context
    stuffing inputs. For those uploads, convert metadata to `.txt` and
    `text/plain` while keeping the file contents unchanged.
    """
    attachment_path = Path(str(attachment.get("path", "")))
    original_name = str(attachment.get("name", "")).strip() or attachment_path.name or "attachment"
    original_mime_type = str(attachment.get("mime_type", "")).strip() or "text/plain"

    lowered_name = original_name.lower()
    lowered_path_suffix = attachment_path.suffix.lower()
    lowered_mime_type = original_mime_type.lower()
    is_csv_attachment = (
        lowered_name.endswith(".csv")
        or lowered_path_suffix == ".csv"
        or lowered_mime_type in {"text/csv", "application/csv"}
    )
    if not is_csv_attachment:
        return original_name, original_mime_type, False

    stem = Path(original_name).stem or Path(attachment_path.name).stem or "attachment"
    return f"{stem}.txt", "text/plain", True


def _inline_attachment_data_into_prompt(
    user_prompt: str,
    attachments: list[Mapping[str, str]] | None,
) -> tuple[str, bool]:
    """Append attachment file contents to the user prompt for text-only fallback."""
    normalized_attachments = _normalize_attachment_inputs(attachments)
    if not normalized_attachments:
        return user_prompt, False

    inline_sections: list[str] = []
    for attachment in normalized_attachments:
        attachment_path = Path(attachment["path"])
        attachment_name = str(attachment.get("name", "")).strip() or attachment_path.name
        try:
            attachment_text = attachment_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
        except OSError:
            continue
        if not attachment_text.strip():
            continue
        inline_sections.append(
            "\n".join(
                [
                    f"--- BEGIN ATTACHMENT: {attachment_name} ---",
                    attachment_text.rstrip(),
                    f"--- END ATTACHMENT: {attachment_name} ---",
                ]
            )
        )

    if not inline_sections:
        return user_prompt, False

    inlined_prompt = "\n\n".join(
        [
            user_prompt.rstrip(),
            "File attachments were unavailable, so the attachment contents are inlined below.",
            "\n\n".join(inline_sections),
        ]
    ).strip()
    return inlined_prompt, True


def _normalize_attachment_input(attachment: Mapping[str, str] | Any) -> dict[str, str] | None:
    if not isinstance(attachment, Mapping):
        return None

    path_value = str(attachment.get("path", "")).strip()
    if not path_value:
        return None

    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return None

    filename = str(attachment.get("name", "")).strip() or path.name
    mime_type = str(attachment.get("mime_type", "")).strip() or "text/csv"
    return {
        "path": str(path),
        "name": filename,
        "mime_type": mime_type,
    }


def _normalize_attachment_inputs(
    attachments: list[Mapping[str, str]] | None,
) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for attachment in attachments or []:
        candidate = _normalize_attachment_input(attachment)
        if candidate is not None:
            normalized.append(candidate)
    return normalized


def _run_with_rate_limit_retries(
    request_fn: Callable[[], str],
    rate_limit_error_type: type[Exception],
    provider_name: str,
) -> str:
    """Retry rate-limited requests with exponential backoff."""
    last_error: Exception | None = None

    for retry_count in range(RATE_LIMIT_MAX_RETRIES + 1):
        try:
            return request_fn()
        except rate_limit_error_type as error:
            last_error = error
            if retry_count >= RATE_LIMIT_MAX_RETRIES:
                break

            retry_after = _extract_retry_after_seconds(error)
            if retry_after is None:
                retry_after = float(2**retry_count)
            logger.warning(
                "%s rate limited (attempt %d/%d), retrying in %.1fs",
                provider_name,
                retry_count + 1,
                RATE_LIMIT_MAX_RETRIES,
                retry_after,
            )
            time.sleep(retry_after)

    detail = f" Details: {last_error}" if last_error else ""
    raise AIProviderError(
        f"{provider_name} rate limit exceeded after {RATE_LIMIT_MAX_RETRIES} retries.{detail}"
    ) from last_error


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider implementation."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_CLAUDE_MODEL,
        attach_csv_as_file: bool = True,
    ) -> None:
        try:
            import anthropic
        except ImportError as error:
            raise AIProviderError(
                "anthropic SDK is not installed. Install it with `pip install anthropic`."
            ) from error

        if not api_key:
            raise AIProviderError(
                "Claude API key is not configured. "
                "Set `ai.claude.api_key` in config.yaml or the ANTHROPIC_API_KEY environment variable."
            )

        self._anthropic = anthropic
        self.api_key = api_key
        self.model = model
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = anthropic.Anthropic(api_key=api_key)
        logger.info("Initialized Claude provider with model %s", model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        def _request() -> str:
            attachment_response = self._request_with_csv_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )
            if attachment_response:
                return attachment_response

            response = self._create_message_with_stream_fallback(
                system_prompt=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                max_tokens=max_tokens,
            )
            text = _extract_anthropic_text(response)
            if not text:
                raise AIProviderError("Claude returned an empty response.")
            return text

        return self._run_claude_request(_request)

    def _run_claude_request(self, request_fn: Callable[[], str]) -> str:
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._anthropic.RateLimitError,
                provider_name="Claude",
            )
        except AIProviderError:
            raise
        except self._anthropic.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to Claude API. Check network access and endpoint configuration."
            ) from error
        except self._anthropic.AuthenticationError as error:
            raise AIProviderError(
                "Claude authentication failed. Check `ai.claude.api_key` or ANTHROPIC_API_KEY."
            ) from error
        except self._anthropic.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "Claude request exceeded the model context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"Claude request was rejected: {error}") from error
        except self._anthropic.APIError as error:
            raise AIProviderError(f"Claude API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected Claude provider error: {error}") from error

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        if not self.attach_csv_as_file:
            return None
        if not attachments:
            return None
        if self._csv_attachment_supported is False:
            return None

        normalized_attachments = _normalize_attachment_inputs(attachments)
        if not normalized_attachments:
            return None

        try:
            content_blocks: list[dict[str, Any]] = [{"type": "text", "text": user_prompt}]
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                mime_type = attachment["mime_type"].lower()
                if mime_type == "application/pdf":
                    encoded_data = base64.b64encode(attachment_path.read_bytes()).decode("ascii")
                    content_blocks.append(
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": encoded_data,
                            },
                        }
                    )
                else:
                    attachment_name = attachment.get("name", attachment_path.name)
                    try:
                        attachment_text = attachment_path.read_text(
                            encoding="utf-8-sig", errors="replace"
                        )
                    except OSError:
                        continue
                    content_blocks.append(
                        {
                            "type": "text",
                            "text": (
                                f"--- BEGIN ATTACHMENT: {attachment_name} ---\n"
                                f"{attachment_text.rstrip()}\n"
                                f"--- END ATTACHMENT: {attachment_name} ---"
                            ),
                        }
                    )

            response = self._create_message_with_stream_fallback(
                system_prompt=system_prompt,
                messages=[{"role": "user", "content": content_blocks}],
                max_tokens=max_tokens,
            )
            text = _extract_anthropic_text(response)
            if not text:
                raise AIProviderError("Claude returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "Claude endpoint does not support CSV attachments; "
                    "falling back to standard text mode."
                )
                return None
            raise

    def _create_message_with_stream_fallback(
        self,
        system_prompt: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
    ) -> Any:
        request_kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": messages,
        }
        try:
            return self._create_non_stream_with_token_limit_retry(request_kwargs)
        except ValueError as error:
            if not _is_anthropic_streaming_required_error(error):
                raise
            logger.info(
                "Claude SDK requires streaming for long request; retrying with messages.stream()."
            )
            return self._create_stream_with_token_limit_retry(request_kwargs)

    def _create_non_stream_with_token_limit_retry(self, request_kwargs: Mapping[str, Any]) -> Any:
        effective_kwargs: dict[str, Any] = dict(request_kwargs)
        for _ in range(2):
            try:
                return self.client.messages.create(**effective_kwargs)
            except self._anthropic.BadRequestError as error:
                requested_tokens = int(effective_kwargs.get("max_tokens", 0))
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=requested_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "Claude rejected max_tokens=%d; retrying with max_tokens=%d.",
                    requested_tokens,
                    retry_token_count,
                )
                effective_kwargs["max_tokens"] = retry_token_count
        return self.client.messages.create(**effective_kwargs)

    def _create_stream_with_token_limit_retry(self, request_kwargs: Mapping[str, Any]) -> Any:
        effective_kwargs: dict[str, Any] = dict(request_kwargs)
        for _ in range(2):
            try:
                with self.client.messages.stream(**effective_kwargs) as stream:
                    return stream.get_final_message()
            except self._anthropic.BadRequestError as error:
                requested_tokens = int(effective_kwargs.get("max_tokens", 0))
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=requested_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "Claude rejected max_tokens=%d during streamed request; retrying with max_tokens=%d.",
                    requested_tokens,
                    retry_token_count,
                )
                effective_kwargs["max_tokens"] = retry_token_count
        with self.client.messages.stream(**effective_kwargs) as stream:
            return stream.get_final_message()

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "claude", "model": self.model}


class OpenAIProvider(AIProvider):
    """OpenAI API provider implementation."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_OPENAI_MODEL,
        attach_csv_as_file: bool = True,
    ) -> None:
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        if not api_key:
            raise AIProviderError(
                "OpenAI API key is not configured. "
                "Set `ai.openai.api_key` in config.yaml or the OPENAI_API_KEY environment variable."
            )

        self._openai = openai
        self.api_key = api_key
        self.model = model
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(api_key=api_key)
        logger.info("Initialized OpenAI provider with model %s", model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_openai_request(_request)

    def _run_openai_request(self, request_fn: Callable[[], str]) -> str:
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="OpenAI",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to OpenAI API. Check network access and endpoint configuration."
            ) from error
        except self._openai.AuthenticationError as error:
            raise AIProviderError(
                "OpenAI authentication failed. Check `ai.openai.api_key` or OPENAI_API_KEY."
            ) from error
        except self._openai.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "OpenAI request exceeded the model context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"OpenAI request was rejected: {error}") from error
        except self._openai.APIError as error:
            raise AIProviderError(f"OpenAI API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected OpenAI provider error: {error}") from error

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            return attachment_response

        prompt_for_completion = user_prompt
        if attachments and self.attach_csv_as_file:
            prompt_for_completion, inlined_attachment_data = _inline_attachment_data_into_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )
            if inlined_attachment_data:
                logger.info("OpenAI attachment fallback inlined attachment data into prompt.")

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt_for_completion},
        ]
        response = self._create_chat_completion(
            messages=messages,
            max_tokens=max_tokens,
        )
        text = _extract_openai_text(response)
        if not text:
            raise AIProviderError("OpenAI returned an empty response.")
        return text

    def _create_chat_completion(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> Any:
        def _create_with_token_parameter(token_parameter: str, token_count: int) -> Any:
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                token_parameter: token_count,
            }
            try:
                return self.client.chat.completions.create(**request_kwargs)
            except self._openai.BadRequestError as error:
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=token_count,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "OpenAI rejected %s=%d; retrying with %s=%d.",
                    token_parameter,
                    token_count,
                    token_parameter,
                    retry_token_count,
                )
                request_kwargs[token_parameter] = retry_token_count
                return self.client.chat.completions.create(**request_kwargs)

        try:
            return _create_with_token_parameter(
                token_parameter="max_completion_tokens",
                token_count=max_tokens,
            )
        except self._openai.BadRequestError as error:
            if not _is_unsupported_parameter_error(error, "max_completion_tokens"):
                raise
            return _create_with_token_parameter(
                token_parameter="max_tokens",
                token_count=max_tokens,
            )

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        if not self.attach_csv_as_file:
            return None
        if not attachments:
            return None
        if self._csv_attachment_supported is False:
            return None
        if not hasattr(self.client, "files") or not hasattr(self.client, "responses"):
            self._csv_attachment_supported = False
            return None

        normalized_attachments = _normalize_attachment_inputs(attachments)
        if not normalized_attachments:
            return None

        uploaded_file_ids: list[str] = []
        try:
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                upload_name, upload_mime_type, converted_from_csv = _prepare_openai_attachment_upload(
                    attachment
                )
                if converted_from_csv:
                    logger.debug(
                        "Converting OpenAI attachment upload from CSV to TXT: %s -> %s",
                        attachment.get("name", attachment_path.name),
                        upload_name,
                    )
                with attachment_path.open("rb") as handle:
                    uploaded = self.client.files.create(
                        file=(upload_name, handle.read(), upload_mime_type),
                        purpose="assistants",
                    )

                file_id = getattr(uploaded, "id", None)
                if file_id is None and isinstance(uploaded, dict):
                    file_id = uploaded.get("id")
                if not isinstance(file_id, str) or not file_id.strip():
                    raise AIProviderError("OpenAI file upload returned no file id.")
                uploaded_file_ids.append(file_id)

            user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
            for file_id in uploaded_file_ids:
                user_content.append({"type": "input_file", "file_id": file_id})

            response_request: dict[str, Any] = {
                "model": self.model,
                "input": [
                    {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                    {"role": "user", "content": user_content},
                ],
                "max_output_tokens": max_tokens,
            }
            try:
                response = self.client.responses.create(**response_request)
            except self._openai.BadRequestError as error:
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=max_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "OpenAI rejected max_output_tokens=%d; retrying with max_output_tokens=%d.",
                    max_tokens,
                    retry_token_count,
                )
                response_request["max_output_tokens"] = retry_token_count
                response = self.client.responses.create(**response_request)
            text = _extract_openai_responses_text(response)
            if not text:
                raise AIProviderError("OpenAI returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "OpenAI endpoint does not support CSV attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise
        finally:
            for uploaded_file_id in uploaded_file_ids:
                try:
                    self.client.files.delete(uploaded_file_id)
                except Exception:
                    continue

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "openai", "model": self.model}


class KimiProvider(AIProvider):
    """Moonshot Kimi API provider implementation."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_KIMI_MODEL,
        base_url: str = DEFAULT_KIMI_BASE_URL,
        attach_csv_as_file: bool = True,
    ) -> None:
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        if not api_key:
            raise AIProviderError(
                "Kimi API key is not configured. "
                "Set `ai.kimi.api_key` in config.yaml or the MOONSHOT_API_KEY environment variable."
            )

        self._openai = openai
        self.api_key = api_key
        self.model = _normalize_kimi_model_name(model)
        self.base_url = _normalize_openai_compatible_base_url(
            base_url=base_url,
            default_base_url=DEFAULT_KIMI_BASE_URL,
        )
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(api_key=api_key, base_url=self.base_url)
        logger.info("Initialized Kimi provider at %s with model %s", self.base_url, self.model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_kimi_request(_request)

    def _run_kimi_request(self, request_fn: Callable[[], str]) -> str:
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="Kimi",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to Kimi API. Check `ai.kimi.base_url` and network access."
            ) from error
        except self._openai.AuthenticationError as error:
            raise AIProviderError(
                "Kimi authentication failed. Check `ai.kimi.api_key`, MOONSHOT_API_KEY, or KIMI_API_KEY."
            ) from error
        except self._openai.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "Kimi request exceeded the model context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"Kimi request was rejected: {error}") from error
        except self._openai.APIError as error:
            if _is_kimi_model_not_available_error(error):
                raise AIProviderError(
                    "Kimi rejected the configured model. "
                    f"Current model: `{self.model}`. "
                    "Set `ai.kimi.model` to a model enabled for your Moonshot account "
                    "(for example `kimi-k2-turbo-preview`) and retry."
                ) from error
            raise AIProviderError(f"Kimi API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected Kimi provider error: {error}") from error

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            return attachment_response

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        text = _extract_openai_text(response)
        if not text:
            raise AIProviderError("Kimi returned an empty response.")
        return text

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        if not self.attach_csv_as_file:
            return None
        if not attachments:
            return None
        if self._csv_attachment_supported is False:
            return None
        if not hasattr(self.client, "files") or not hasattr(self.client, "responses"):
            self._csv_attachment_supported = False
            return None

        normalized_attachments = _normalize_attachment_inputs(attachments)
        if not normalized_attachments:
            return None

        uploaded_file_ids: list[str] = []
        try:
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                with attachment_path.open("rb") as handle:
                    uploaded = self.client.files.create(
                        file=(attachment["name"], handle.read(), attachment["mime_type"]),
                        purpose=DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
                    )

                file_id = getattr(uploaded, "id", None)
                if file_id is None and isinstance(uploaded, dict):
                    file_id = uploaded.get("id")
                if not isinstance(file_id, str) or not file_id.strip():
                    raise AIProviderError("Kimi file upload returned no file id.")
                uploaded_file_ids.append(file_id)

            user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
            for file_id in uploaded_file_ids:
                user_content.append({"type": "input_file", "file_id": file_id})

            response = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                    {"role": "user", "content": user_content},
                ],
                max_output_tokens=max_tokens,
            )
            text = _extract_openai_responses_text(response)
            if not text:
                raise AIProviderError("Kimi returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "Kimi endpoint does not support CSV attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise
        finally:
            for uploaded_file_id in uploaded_file_ids:
                try:
                    self.client.files.delete(uploaded_file_id)
                except Exception:
                    continue

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "kimi", "model": self.model}


class LocalProvider(AIProvider):
    """OpenAI-compatible local provider implementation."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "not-needed",
        attach_csv_as_file: bool = True,
    ) -> None:
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        self._openai = openai
        self.base_url = _normalize_openai_compatible_base_url(
            base_url=base_url,
            default_base_url=DEFAULT_LOCAL_BASE_URL,
        )
        self.model = model
        self.api_key = api_key
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(api_key=api_key, base_url=self.base_url)
        logger.info("Initialized local provider at %s with model %s", self.base_url, model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_local_request(_request)

    def _run_local_request(self, request_fn: Callable[[], str]) -> str:
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="Local provider",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to local AI endpoint. Check `ai.local.base_url` and ensure the server is running."
            ) from error
        except self._openai.AuthenticationError as error:
            raise AIProviderError(
                "Local AI endpoint rejected authentication. Check `ai.local.api_key` if your server requires one."
            ) from error
        except self._openai.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "Local model request exceeded the context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"Local provider request was rejected: {error}") from error
        except self._openai.APIError as error:
            error_text = str(error).lower()
            if "404" in error_text or "not found" in error_text:
                raise AIProviderError(
                    "Local AI endpoint returned 404 (not found). "
                    "This is often caused by a base URL missing `/v1`. "
                    f"Current base URL: {self.base_url}"
                ) from error
            raise AIProviderError(f"Local provider API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected local provider error: {error}") from error

    def analyze_with_progress(
        self,
        system_prompt: str,
        user_prompt: str,
        progress_callback: Callable[[dict[str, str]], None] | None,
        attachments: list[Mapping[str, str]] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with streamed progress updates when supported by the local endpoint."""
        if progress_callback is None:
            return self.analyze_with_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                attachments=attachments,
                max_tokens=max_tokens,
            )

        def _request() -> str:
            attachment_response = self._request_with_csv_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )
            if attachment_response:
                cleaned_attachment_response = _strip_leading_reasoning_blocks(attachment_response)
                return cleaned_attachment_response or attachment_response.strip()

            try:
                stream = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    stream=True,
                )
            except self._openai.BadRequestError as error:
                lowered_error = str(error).lower()
                if "stream" in lowered_error and ("unsupported" in lowered_error or "not support" in lowered_error):
                    return self._request_non_stream(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        max_tokens=max_tokens,
                        attachments=attachments,
                    )
                raise

            thinking_parts: list[str] = []
            answer_parts: list[str] = []
            last_emit_at = 0.0
            last_sent_thinking = ""
            last_sent_answer = ""

            for chunk in stream:
                choices = getattr(chunk, "choices", None)
                if not choices:
                    continue
                choice = choices[0]
                delta = getattr(choice, "delta", None)
                if delta is None and isinstance(choice, dict):
                    delta = choice.get("delta")
                if delta is None:
                    continue

                answer_delta = _extract_openai_delta_text(delta, ("content",))
                thinking_delta = _extract_openai_delta_text(
                    delta,
                    ("reasoning_content", "reasoning", "thinking"),
                )

                if thinking_delta:
                    thinking_parts.append(thinking_delta)
                if answer_delta:
                    answer_parts.append(answer_delta)

                current_thinking = "".join(thinking_parts).strip()
                current_answer = _clean_streamed_answer_text(
                    answer_text="".join(answer_parts),
                    thinking_text=current_thinking,
                )

                if not current_thinking and not current_answer:
                    continue

                now = time.monotonic()
                changed = (
                    current_thinking != last_sent_thinking
                    or current_answer != last_sent_answer
                )
                if not changed:
                    continue

                # Throttle UI updates to avoid flooding SSE with tiny chunks.
                if now - last_emit_at < 0.35 and (
                    len(current_thinking) - len(last_sent_thinking) < 80
                    and len(current_answer) - len(last_sent_answer) < 80
                ):
                    continue

                last_emit_at = now
                last_sent_thinking = current_thinking
                last_sent_answer = current_answer
                try:
                    progress_callback(
                        {
                            "status": "thinking",
                            "thinking_text": current_thinking,
                            "partial_text": current_answer,
                        }
                    )
                except Exception:
                    # Progress callbacks are best-effort and must not break analysis.
                    pass

            final_thinking = "".join(thinking_parts).strip()
            final_answer = _clean_streamed_answer_text(
                answer_text="".join(answer_parts),
                thinking_text=final_thinking,
            )
            if final_answer:
                return final_answer

            if final_thinking:
                return final_thinking

            raise AIProviderError(
                "Local AI provider returned an empty streamed response. "
                "Try a different local model or increase max tokens."
            )

        return self._run_local_request(_request)

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            cleaned_attachment_response = _strip_leading_reasoning_blocks(attachment_response)
            if cleaned_attachment_response:
                return cleaned_attachment_response
            return attachment_response.strip()

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        text = _extract_openai_text(response)
        if text:
            cleaned_text = _strip_leading_reasoning_blocks(text)
            if cleaned_text:
                return cleaned_text
            return text.strip()

        finish_reason = None
        choices = getattr(response, "choices", None)
        if choices:
            first_choice = choices[0]
            finish_reason = getattr(first_choice, "finish_reason", None)
            if finish_reason is None and isinstance(first_choice, dict):
                finish_reason = first_choice.get("finish_reason")
        reason_detail = f" (finish_reason={finish_reason})" if finish_reason else ""
        raise AIProviderError(
            "Local AI provider returned an empty response"
            f"{reason_detail}. This can happen with reasoning-only outputs or very low token limits."
        )

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        if not self.attach_csv_as_file:
            return None
        if not attachments:
            return None
        if self._csv_attachment_supported is False:
            return None
        if not hasattr(self.client, "files") or not hasattr(self.client, "responses"):
            self._csv_attachment_supported = False
            return None

        normalized_attachments = _normalize_attachment_inputs(attachments)
        if not normalized_attachments:
            return None

        uploaded_file_ids: list[str] = []
        try:
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                with attachment_path.open("rb") as handle:
                    uploaded = self.client.files.create(
                        file=(attachment["name"], handle.read(), attachment["mime_type"]),
                        purpose="assistants",
                    )

                file_id = getattr(uploaded, "id", None)
                if file_id is None and isinstance(uploaded, dict):
                    file_id = uploaded.get("id")
                if not isinstance(file_id, str) or not file_id.strip():
                    raise AIProviderError("Local provider file upload returned no file id.")
                uploaded_file_ids.append(file_id)

            user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
            for file_id in uploaded_file_ids:
                user_content.append({"type": "input_file", "file_id": file_id})

            response = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                    {"role": "user", "content": user_content},
                ],
                max_output_tokens=max_tokens,
            )
            text = _extract_openai_responses_text(response)
            if not text:
                raise AIProviderError("Local provider returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "Local endpoint does not support file attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise
        finally:
            for uploaded_file_id in uploaded_file_ids:
                try:
                    self.client.files.delete(uploaded_file_id)
                except Exception:
                    continue

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "local", "model": self.model}


def create_provider(config: dict[str, Any]) -> AIProvider:
    """Factory for creating configured AI providers."""
    ai_config = config.get("ai", {})
    if not isinstance(ai_config, dict):
        raise ValueError("Invalid configuration: `ai` section must be a dictionary.")

    provider_name = str(ai_config.get("provider", "claude")).strip().lower()

    if provider_name == "claude":
        claude_config = ai_config.get("claude", {})
        if not isinstance(claude_config, dict):
            raise ValueError("Invalid configuration: `ai.claude` must be a dictionary.")
        api_key = _resolve_api_key(
            str(claude_config.get("api_key", "")),
            "ANTHROPIC_API_KEY",
        )
        return ClaudeProvider(
            api_key=api_key,
            model=str(claude_config.get("model", DEFAULT_CLAUDE_MODEL)),
            attach_csv_as_file=bool(claude_config.get("attach_csv_as_file", True)),
        )

    if provider_name == "openai":
        openai_config = ai_config.get("openai", {})
        if not isinstance(openai_config, dict):
            raise ValueError("Invalid configuration: `ai.openai` must be a dictionary.")
        api_key = _resolve_api_key(
            str(openai_config.get("api_key", "")),
            "OPENAI_API_KEY",
        )
        return OpenAIProvider(
            api_key=api_key,
            model=str(openai_config.get("model", DEFAULT_OPENAI_MODEL)),
            attach_csv_as_file=bool(openai_config.get("attach_csv_as_file", True)),
        )

    if provider_name == "local":
        local_config = ai_config.get("local", {})
        if not isinstance(local_config, dict):
            raise ValueError("Invalid configuration: `ai.local` must be a dictionary.")
        return LocalProvider(
            base_url=str(local_config.get("base_url", DEFAULT_LOCAL_BASE_URL)),
            model=str(local_config.get("model", DEFAULT_LOCAL_MODEL)),
            api_key=str(local_config.get("api_key", "not-needed")),
            attach_csv_as_file=bool(local_config.get("attach_csv_as_file", True)),
        )

    if provider_name == "kimi":
        kimi_config = ai_config.get("kimi", {})
        if not isinstance(kimi_config, dict):
            raise ValueError("Invalid configuration: `ai.kimi` must be a dictionary.")
        api_key = _resolve_api_key_candidates(
            str(kimi_config.get("api_key", "")),
            ("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        )
        return KimiProvider(
            api_key=api_key,
            model=str(kimi_config.get("model", DEFAULT_KIMI_MODEL)),
            base_url=str(kimi_config.get("base_url", DEFAULT_KIMI_BASE_URL)),
            attach_csv_as_file=bool(kimi_config.get("attach_csv_as_file", True)),
        )

    raise ValueError(
        f"Unsupported AI provider '{provider_name}'. Expected one of: claude, openai, kimi, local."
    )


__all__ = [
    "AIProvider",
    "AIProviderError",
    "ClaudeProvider",
    "OpenAIProvider",
    "KimiProvider",
    "LocalProvider",
    "create_provider",
]
