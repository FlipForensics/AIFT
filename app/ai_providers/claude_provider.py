"""Anthropic Claude AI provider implementation.

Uses the ``anthropic`` Python SDK to communicate with the Anthropic
Messages API. Supports synchronous and streaming generation, CSV file
attachments via content blocks, and automatic token-limit retry.

Attributes:
    logger: Module-level logger for Claude provider operations.
"""

from __future__ import annotations

import base64
import logging
import threading
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .base import (
    AIProvider,
    AIProviderError,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    _is_attachment_unsupported_error,
    _is_anthropic_streaming_required_error,
    _normalize_api_key_value,
    _resolve_completion_token_retry_limit,
    _resolve_timeout_seconds,
    _run_with_rate_limit_retries,
    _T,
)
from .utils import (
    _extract_anthropic_stream_text,
    _extract_anthropic_text,
    _inline_attachment_data_into_prompt,
)

logger = logging.getLogger(__name__)


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider implementation.

    Supports both synchronous and streaming generation, CSV file attachments
    via content blocks (base64-encoded PDFs or inline text), and automatic
    token-limit retry when ``max_tokens`` exceeds the model's maximum.

    Attributes:
        _api_key (str): The Anthropic API key (private to reduce
            accidental exposure in repr/debug output).
        model (str): The Claude model identifier.
        attach_csv_as_file (bool): Whether to upload CSV artifacts as
            content blocks.
        request_timeout_seconds (float): HTTP timeout in seconds.
        client: The ``anthropic.Anthropic`` SDK client instance.
    """

    _provider_display_name: str = "Claude"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_CLAUDE_MODEL,
        attach_csv_as_file: bool = True,
        request_timeout_seconds: float = DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the Claude provider.

        Args:
            api_key: Anthropic API key. Must be non-empty.
            model: Claude model identifier.
            attach_csv_as_file: If ``True``, send CSV artifacts as structured
                content blocks.
            request_timeout_seconds: HTTP timeout in seconds.

        Raises:
            AIProviderError: If the ``anthropic`` SDK is not installed or
                the API key is empty.
        """
        try:
            import anthropic
        except ImportError as error:
            raise AIProviderError(
                "anthropic SDK is not installed. Install it with `pip install anthropic`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key)
        if not normalized_api_key:
            raise AIProviderError(
                "Claude API key is not configured. "
                "Set `ai.claude.api_key` in config.yaml or the ANTHROPIC_API_KEY environment variable."
            )

        self._anthropic = anthropic
        self._api_key = normalized_api_key
        self.model = model
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self._attachment_lock = threading.Lock()
        self._rate_limit_error_class = anthropic.RateLimitError
        self.request_timeout_seconds = _resolve_timeout_seconds(
            request_timeout_seconds,
            DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
        )
        self.client = anthropic.Anthropic(
            api_key=normalized_api_key,
            timeout=self.request_timeout_seconds,
        )
        logger.info("Initialized Claude provider with model %s (timeout %.1fs)", model, self.request_timeout_seconds)

    def _map_api_error(self, error: Exception) -> AIProviderError:
        """Map an Anthropic SDK exception to an ``AIProviderError``.

        Overrides the base implementation to provide Claude-specific error
        messages referencing the correct config keys.

        Args:
            error: The raw SDK or network exception.

        Returns:
            An ``AIProviderError`` with a user-friendly message.
        """
        if isinstance(error, self._anthropic.APIConnectionError):
            return AIProviderError(
                "Unable to connect to Claude API. Check network access and endpoint configuration."
            )
        if isinstance(error, self._anthropic.AuthenticationError):
            return AIProviderError(
                "Claude authentication failed. Check `ai.claude.api_key` or ANTHROPIC_API_KEY."
            )
        return super()._map_api_error(error)

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from Claude.

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
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "stream": True,
            }
            try:
                stream = _run_with_rate_limit_retries(
                    request_fn=lambda: self._with_token_limit_retry(
                        lambda kw: self.client.messages.create(**kw),
                        request_kwargs,
                    ),
                    rate_limit_error_type=self._anthropic.RateLimitError,
                    provider_name="Claude",
                )
                emitted = False
                for event in stream:
                    chunk_text = _extract_anthropic_stream_text(event)
                    if not chunk_text:
                        continue
                    emitted = True
                    yield chunk_text
                if not emitted:
                    raise AIProviderError("Claude returned an empty response.")
            except AIProviderError:
                raise
            except Exception as error:
                raise self._map_api_error(error) from error

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via Claude content blocks.

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
            attachment_response = self._request_with_csv_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )
            if attachment_response:
                return attachment_response

            effective_prompt = user_prompt
            if attachments:
                effective_prompt, inlined = _inline_attachment_data_into_prompt(
                    user_prompt=user_prompt,
                    attachments=attachments,
                )
                if inlined:
                    logger.info("Claude attachment fallback inlined attachment data into prompt.")

            response = self._create_message_with_stream_fallback(
                system_prompt=system_prompt,
                messages=[{"role": "user", "content": effective_prompt}],
                max_tokens=max_tokens,
            )
            text = _extract_anthropic_text(response)
            if not text:
                raise AIProviderError("Claude returned an empty response.")
            return text

        return self._run_request(_request)

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        """Attempt to send a request with CSV files as Claude content blocks.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated text if attachment mode succeeded, or ``None``
            if attachments were skipped or unsupported.
        """
        normalized_attachments = self._prepare_csv_attachments(attachments)
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

            with self._attachment_lock:
                self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                with self._attachment_lock:
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
        """Create a Claude message, falling back to streaming for long requests.

        Args:
            system_prompt: The system-level instruction text.
            messages: The conversation messages list.
            max_tokens: Maximum completion tokens.

        Returns:
            The Anthropic ``Message`` response object.
        """
        request_kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": messages,
        }
        try:
            return self._with_token_limit_retry(
                lambda kw: self.client.messages.create(**kw),
                request_kwargs,
            )
        except ValueError as error:
            if not _is_anthropic_streaming_required_error(error):
                raise
            logger.info(
                "Claude SDK requires streaming for long request; retrying with messages.stream()."
            )
            return self._with_token_limit_retry(
                lambda kw: self._stream_and_collect(**kw),
                request_kwargs,
            )

    def _stream_and_collect(self, **kwargs: Any) -> Any:
        """Stream a Claude request and return the final message.

        Args:
            **kwargs: Keyword arguments for ``client.messages.stream``.

        Returns:
            The final Anthropic ``Message`` response object.
        """
        with self.client.messages.stream(**kwargs) as stream:
            return stream.get_final_message()

    def _with_token_limit_retry(
        self,
        create_fn: Callable[[dict[str, Any]], Any],
        request_kwargs: dict[str, Any],
    ) -> Any:
        """Execute a Claude API call with automatic token-limit retry.

        If the initial request is rejected because ``max_tokens`` exceeds
        the model's supported maximum, retries once with the lower limit
        extracted from the error message.

        This single method replaces the three near-identical retry methods
        that existed previously.

        Args:
            create_fn: A callable that takes the request kwargs dict and
                performs the API call.
            request_kwargs: Keyword arguments for the API call.

        Returns:
            The API response object.

        Raises:
            anthropic.BadRequestError: If the request fails for a reason
                other than token limits, or if the retry also fails.
        """
        effective_kwargs: dict[str, Any] = dict(request_kwargs)
        try:
            return create_fn(effective_kwargs)
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
        return create_fn(effective_kwargs)

    def get_model_info(self) -> dict[str, str]:
        """Return Claude provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` and ``"model"`` keys.
        """
        return {"provider": "claude", "model": self.model}
