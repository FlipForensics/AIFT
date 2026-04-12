"""OpenAI API provider implementation.

Uses the ``openai`` Python SDK to communicate with the OpenAI Chat
Completions and Responses APIs. Supports synchronous and streaming
generation, CSV file attachments via the Responses API, and automatic
fallback between ``max_completion_tokens`` and ``max_tokens`` parameters.

Attributes:
    logger: Module-level logger for OpenAI provider operations.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Iterator, Mapping

from .base import (
    AIProvider,
    AIProviderError,
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    DEFAULT_OPENAI_MODEL,
    RATE_LIMIT_MAX_RETRIES,
    _extract_retry_after_seconds,
    _is_attachment_unsupported_error,
    _is_unsupported_parameter_error,
    _normalize_api_key_value,
    _resolve_completion_token_retry_limit,
    _resolve_timeout_seconds,
)
from .utils import (
    _extract_openai_delta_text,
    _extract_openai_text,
    _inline_attachment_data_into_prompt,
    upload_and_request_via_responses_api,
)

logger = logging.getLogger(__name__)


class OpenAIProvider(AIProvider):
    """OpenAI API provider implementation.

    Attributes:
        _api_key (str): The OpenAI API key (private to reduce
            accidental exposure in repr/debug output).
        model (str): The OpenAI model identifier.
        attach_csv_as_file (bool): Whether to upload CSV artifacts as
            file attachments via the Responses API.
        request_timeout_seconds (float): HTTP timeout in seconds.
        client: The ``openai.OpenAI`` SDK client instance.
    """

    _provider_display_name: str = "OpenAI"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_OPENAI_MODEL,
        attach_csv_as_file: bool = True,
        request_timeout_seconds: float = DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key. Must be non-empty.
            model: OpenAI model identifier.
            attach_csv_as_file: If ``True``, attempt file uploads via
                the Responses API.
            request_timeout_seconds: HTTP timeout in seconds.

        Raises:
            AIProviderError: If the ``openai`` SDK is not installed or
                the API key is empty.
        """
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key)
        if not normalized_api_key:
            raise AIProviderError(
                "OpenAI API key is not configured. "
                "Set `ai.openai.api_key` in config.yaml or the OPENAI_API_KEY environment variable."
            )

        self._openai = openai
        self._api_key = normalized_api_key
        self.model = model
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self._attachment_lock = threading.Lock()
        self._rate_limit_error_class = openai.RateLimitError
        self.request_timeout_seconds = _resolve_timeout_seconds(
            request_timeout_seconds,
            DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
        )
        self.client = openai.OpenAI(
            api_key=normalized_api_key,
            timeout=self.request_timeout_seconds,
        )
        logger.info("Initialized OpenAI provider with model %s (timeout %.1fs)", model, self.request_timeout_seconds)

    def _map_api_error(self, error: Exception) -> AIProviderError:
        """Map an OpenAI SDK exception to an ``AIProviderError``.

        Overrides the base implementation to provide OpenAI-specific error
        messages referencing the correct config keys.

        Args:
            error: The raw SDK or network exception.

        Returns:
            An ``AIProviderError`` with a user-friendly message.
        """
        if isinstance(error, self._openai.AuthenticationError):
            return AIProviderError(
                "OpenAI authentication failed. Check `ai.openai.api_key` or OPENAI_API_KEY."
            )
        return super()._map_api_error(error)

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from OpenAI.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Yields:
            Text chunk strings as they are generated.

        Raises:
            AIProviderError: On empty response or API failure.
        """
        def _stream() -> Iterator[str]:
            """Inner generator with rate-limit retry around create + iterate."""
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            last_rate_limit_error: Exception | None = None
            for attempt in range(RATE_LIMIT_MAX_RETRIES + 1):
                try:
                    stream = self._create_chat_completion(
                        messages=messages,
                        max_tokens=max_tokens,
                        stream=True,
                    )
                    emitted = False
                    for chunk in stream:
                        choices = getattr(chunk, "choices", None)
                        if not choices:
                            continue
                        choice = choices[0]
                        delta = getattr(choice, "delta", None)
                        if delta is None and isinstance(choice, dict):
                            delta = choice.get("delta")
                        chunk_text = _extract_openai_delta_text(
                            delta,
                            ("content", "reasoning_content", "reasoning", "refusal"),
                        )
                        if not chunk_text:
                            continue
                        emitted = True
                        yield chunk_text
                    if not emitted:
                        raise AIProviderError("OpenAI returned an empty response.")
                    return
                except self._openai.RateLimitError as rate_error:
                    last_rate_limit_error = rate_error
                    if attempt >= RATE_LIMIT_MAX_RETRIES:
                        break
                    retry_after = _extract_retry_after_seconds(rate_error)
                    if retry_after is None:
                        retry_after = float(2 ** attempt)
                    logger.warning(
                        "OpenAI stream rate limited (attempt %d/%d), retrying in %.1fs",
                        attempt + 1,
                        RATE_LIMIT_MAX_RETRIES,
                        retry_after,
                    )
                    time.sleep(retry_after)
                except AIProviderError:
                    raise
                except Exception as error:
                    raise self._map_api_error(error) from error

            raise AIProviderError(
                f"OpenAI rate limit exceeded after {RATE_LIMIT_MAX_RETRIES} retries. "
                f"Details: {last_rate_limit_error}"
            )

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via the Responses API.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_request(_request)

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        """Perform a non-streaming OpenAI request with attachment handling.

        Tries file-attachment mode first, then falls back to inlining
        attachment data, and finally issues a plain Chat Completions request.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: If the response is empty.
        """
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            return attachment_response

        prompt_for_completion = user_prompt
        if attachments:
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
        stream: bool = False,
    ) -> Any:
        """Create a Chat Completions request with token parameter fallback.

        Tries ``max_completion_tokens`` first, then falls back to
        ``max_tokens`` if the endpoint reports the parameter as unsupported.
        Also retries with a reduced token count when the provider rejects
        the requested maximum.

        Args:
            messages: The conversation messages list.
            max_tokens: Maximum completion tokens.
            stream: If ``True``, return a streaming response iterator.

        Returns:
            The OpenAI ``ChatCompletion`` response or streaming iterator.
        """
        def _create_with_token_parameter(token_parameter: str, token_count: int) -> Any:
            """Try creating with a specific token parameter, retrying on token limit."""
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                token_parameter: token_count,
            }
            if stream:
                request_kwargs["stream"] = True
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
        """Attempt to send a request with CSV files via the Responses API.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated text if succeeded, or ``None`` if skipped.
        """
        normalized_attachments = self._prepare_csv_attachments(
            attachments,
            supports_file_attachments=hasattr(self.client, "files") and hasattr(self.client, "responses"),
        )
        if not normalized_attachments:
            return None

        try:
            text = upload_and_request_via_responses_api(
                client=self.client,
                openai_module=self._openai,
                model=self.model,
                normalized_attachments=normalized_attachments,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                provider_name="OpenAI",
                upload_purpose="assistants",
                convert_csv_to_txt=True,
            )
            with self._attachment_lock:
                self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                with self._attachment_lock:
                    self._csv_attachment_supported = False
                logger.info(
                    "OpenAI endpoint does not support CSV attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise

    def get_model_info(self) -> dict[str, str]:
        """Return OpenAI provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` and ``"model"`` keys.
        """
        return {"provider": "openai", "model": self.model}
