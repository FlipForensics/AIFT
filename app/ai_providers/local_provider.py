"""OpenAI-compatible local provider implementation.

Uses the ``openai`` Python SDK pointed at a local endpoint (Ollama,
LM Studio, vLLM, or similar). Supports synchronous and streaming
generation, CSV file attachments via the Responses API when available,
automatic reasoning-block stripping for local reasoning models, and
configurable request timeouts.

Attributes:
    logger: Module-level logger for local provider operations.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterator, Mapping

from .base import (
    AIProvider,
    AIProviderError,
    DEFAULT_LOCAL_BASE_URL,
    DEFAULT_MAX_TOKENS,
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    _is_attachment_unsupported_error,
    _is_context_length_error,
    _normalize_api_key_value,
    _normalize_openai_compatible_base_url,
    _resolve_timeout_seconds,
    _run_with_rate_limit_retries,
    _T,
)
from .utils import (
    _clean_streamed_answer_text,
    _extract_openai_delta_text,
    _extract_openai_text,
    _inline_attachment_data_into_prompt,
    _strip_leading_reasoning_blocks,
    upload_and_request_via_responses_api,
)

logger = logging.getLogger(__name__)

DEFAULT_LOCAL_MODEL = "llama3.1:70b"


class LocalProvider(AIProvider):
    """OpenAI-compatible local provider implementation.

    Attributes:
        base_url (str): The normalized local endpoint base URL.
        model (str): The local model identifier.
        api_key (str): The API key for the local endpoint.
        attach_csv_as_file (bool): Whether to attempt file-attachment mode.
        request_timeout_seconds (float): HTTP timeout in seconds.
        client: The ``openai.OpenAI`` SDK client instance.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "not-needed",
        attach_csv_as_file: bool = True,
        request_timeout_seconds: float = DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the local provider.

        Args:
            base_url: Base URL for the local endpoint. Normalized to
                include ``/v1`` if missing.
            model: Model identifier.
            api_key: API key. Defaults to ``"not-needed"``.
            attach_csv_as_file: If ``True``, attempt file uploads.
            request_timeout_seconds: HTTP timeout in seconds.

        Raises:
            AIProviderError: If the ``openai`` SDK is not installed.
        """
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key) or "not-needed"

        self._openai = openai
        self.base_url = _normalize_openai_compatible_base_url(
            base_url=base_url,
            default_base_url=DEFAULT_LOCAL_BASE_URL,
        )
        self.model = model
        self.api_key = normalized_api_key
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self.request_timeout_seconds = _resolve_timeout_seconds(
            request_timeout_seconds,
            DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
        )
        self._api_timeout_error_type = getattr(openai, "APITimeoutError", None)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(
            api_key=normalized_api_key,
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
            max_retries=0,
        )
        logger.info(
            "Initialized local provider at %s with model %s (timeout %.1fs)",
            self.base_url,
            model,
            self.request_timeout_seconds,
        )

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to the local endpoint and return the generated text.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from the local endpoint.

        Falls back to non-streaming if the endpoint reports streaming
        is unsupported.

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
            try:
                prompt_for_completion = self._build_chat_completion_prompt(
                    user_prompt=user_prompt,
                    attachments=None,
                )
                try:
                    stream = _run_with_rate_limit_retries(
                        request_fn=lambda: self.client.chat.completions.create(
                            model=self.model,
                            max_tokens=max_tokens,
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": prompt_for_completion},
                            ],
                            stream=True,
                        ),
                        rate_limit_error_type=self._openai.RateLimitError,
                        provider_name="Local provider",
                    )
                except self._openai.BadRequestError as error:
                    lowered_error = str(error).lower()
                    if "stream" in lowered_error and ("unsupported" in lowered_error or "not support" in lowered_error):
                        fallback_text = self._request_non_stream(
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            max_tokens=max_tokens,
                            attachments=None,
                        )
                        if fallback_text:
                            yield fallback_text
                            return
                    raise

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
                        ("content", "reasoning_content", "reasoning", "thinking"),
                    )
                    if not chunk_text:
                        continue
                    emitted = True
                    yield chunk_text

                if not emitted:
                    raise AIProviderError(
                        "Local AI provider returned an empty streamed response. "
                        "Try a different local model or increase max tokens."
                    )
            except AIProviderError:
                raise
            except self._openai.APIConnectionError as error:
                self._raise_connection_error(error)
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
                self._raise_api_error(error)
            except Exception as error:
                raise AIProviderError(f"Unexpected local provider error: {error}") from error

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments.

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

        return self._run_local_request(_request)

    def _run_local_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute a local request with rate-limit retries and error mapping.

        Args:
            request_fn: A zero-argument callable that performs the request.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On any OpenAI SDK error (with local messages).
        """
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="Local provider",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            self._raise_connection_error(error)
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
            self._raise_api_error(error)
        except Exception as error:
            raise AIProviderError(f"Unexpected local provider error: {error}") from error

    def _raise_connection_error(self, error: Exception) -> None:
        """Map APIConnectionError to AIProviderError with timeout detection.

        Args:
            error: The connection error to map.

        Raises:
            AIProviderError: Always raised with appropriate message.
        """
        if (
            self._api_timeout_error_type is not None
            and isinstance(error, self._api_timeout_error_type)
        ) or "timeout" in str(error).lower():
            raise AIProviderError(
                "Local AI request timed out after "
                f"{self.request_timeout_seconds:g} seconds. "
                "Increase `ai.local.request_timeout_seconds` for long-running prompts."
            ) from error
        raise AIProviderError(
            "Unable to connect to local AI endpoint. Check `ai.local.base_url` and ensure the server is running."
        ) from error

    def _raise_api_error(self, error: Exception) -> None:
        """Map APIError to AIProviderError with 404 detection.

        Args:
            error: The API error to map.

        Raises:
            AIProviderError: Always raised with appropriate message.
        """
        error_text = str(error).lower()
        if "404" in error_text or "not found" in error_text:
            raise AIProviderError(
                "Local AI endpoint returned 404 (not found). "
                "This is often caused by a base URL missing `/v1`. "
                f"Current base URL: {self.base_url}"
            ) from error
        raise AIProviderError(f"Local provider API error: {error}") from error

    def analyze_with_progress(
        self,
        system_prompt: str,
        user_prompt: str,
        progress_callback: Callable[[dict[str, str]], None] | None,
        attachments: list[Mapping[str, str]] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with streamed progress updates when supported.

        Streams the response and periodically invokes ``progress_callback``
        with accumulated thinking and answer text. Falls back to
        ``analyze_with_attachments`` when no callback is provided.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            progress_callback: Optional callable receiving progress dicts.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text with reasoning blocks removed.

        Raises:
            AIProviderError: On empty response or API failure.
        """
        if progress_callback is None:
            return self.analyze_with_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                attachments=attachments,
                max_tokens=max_tokens,
            )

        def _request() -> str:
            result = self._build_stream_or_result(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )
            if isinstance(result, str):
                return result
            stream = result

            thinking_parts: list[str] = []
            answer_parts: list[str] = []
            last_emit_at = 0.0
            last_sent_thinking = ""
            last_sent_answer = ""

            for chunk in stream:
                chunk_result = self._process_stream_chunk(chunk)
                if chunk_result is None:
                    continue

                thinking_delta, answer_delta = chunk_result
                if thinking_delta:
                    thinking_parts.append(thinking_delta)
                if answer_delta:
                    answer_parts.append(answer_delta)

                current_thinking = "".join(thinking_parts).strip()
                current_answer = _clean_streamed_answer_text(
                    answer_text="".join(answer_parts),
                    thinking_text=current_thinking,
                )

                last_emit_at, last_sent_thinking, last_sent_answer = (
                    self._emit_progress_if_needed(
                        progress_callback=progress_callback,
                        current_thinking=current_thinking,
                        current_answer=current_answer,
                        last_emit_at=last_emit_at,
                        last_sent_thinking=last_sent_thinking,
                        last_sent_answer=last_sent_answer,
                    )
                )

            return self._finalize_stream_response(thinking_parts, answer_parts)

        return self._run_local_request(_request)

    def _build_stream_or_result(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> Any | str:
        """Set up the streaming request, returning a stream or a final string.

        Attempts CSV file attachment first. If that succeeds, returns the
        completed text directly. Otherwise creates a streaming chat completion.
        Falls back to non-streaming if the endpoint rejects streaming.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            A streaming response object, or a ``str`` if the result was
            obtained without streaming (attachment path or fallback).

        Raises:
            AIProviderError: If the non-streaming fallback also fails.
        """
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            cleaned = _strip_leading_reasoning_blocks(attachment_response)
            return cleaned or attachment_response.strip()

        prompt_for_completion = self._build_chat_completion_prompt(
            user_prompt=user_prompt,
            attachments=attachments,
        )

        try:
            return self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt_for_completion},
                ],
                stream=True,
            )
        except self._openai.BadRequestError as error:
            lowered_error = str(error).lower()
            if "stream" in lowered_error and (
                "unsupported" in lowered_error or "not support" in lowered_error
            ):
                return self._request_non_stream(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=max_tokens,
                    attachments=attachments,
                )
            raise

    @staticmethod
    def _process_stream_chunk(chunk: Any) -> tuple[str, str] | None:
        """Extract thinking and answer deltas from a single stream chunk.

        Args:
            chunk: A streaming response chunk from the OpenAI SDK.

        Returns:
            A ``(thinking_delta, answer_delta)`` tuple, or ``None`` if the
            chunk contains no usable text.
        """
        choices = getattr(chunk, "choices", None)
        if not choices:
            return None
        choice = choices[0]
        delta = getattr(choice, "delta", None)
        if delta is None and isinstance(choice, dict):
            delta = choice.get("delta")
        if delta is None:
            return None

        answer_delta = _extract_openai_delta_text(delta, ("content",))
        thinking_delta = _extract_openai_delta_text(
            delta,
            ("reasoning_content", "reasoning", "thinking"),
        )

        if not answer_delta and not thinking_delta:
            return None
        return (thinking_delta, answer_delta)

    @staticmethod
    def _emit_progress_if_needed(
        progress_callback: Callable[[dict[str, str]], None],
        current_thinking: str,
        current_answer: str,
        last_emit_at: float,
        last_sent_thinking: str,
        last_sent_answer: str,
    ) -> tuple[float, str, str]:
        """Send a progress callback if enough content has changed.

        Applies rate-limiting so the callback fires at most every 0.35 s
        unless at least 80 characters have been added to either channel.

        Args:
            progress_callback: The callable to invoke with progress data.
            current_thinking: Accumulated thinking text so far.
            current_answer: Accumulated answer text so far.
            last_emit_at: Monotonic timestamp of the last emission.
            last_sent_thinking: Thinking text sent in the last emission.
            last_sent_answer: Answer text sent in the last emission.

        Returns:
            Updated ``(last_emit_at, last_sent_thinking, last_sent_answer)``.
        """
        if not current_thinking and not current_answer:
            return last_emit_at, last_sent_thinking, last_sent_answer

        changed = (
            current_thinking != last_sent_thinking
            or current_answer != last_sent_answer
        )
        if not changed:
            return last_emit_at, last_sent_thinking, last_sent_answer

        now = time.monotonic()
        if now - last_emit_at < 0.35 and (
            len(current_thinking) - len(last_sent_thinking) < 80
            and len(current_answer) - len(last_sent_answer) < 80
        ):
            return last_emit_at, last_sent_thinking, last_sent_answer

        try:
            progress_callback(
                {
                    "status": "thinking",
                    "thinking_text": current_thinking,
                    "partial_text": current_answer,
                }
            )
        except Exception:
            pass

        return now, current_thinking, current_answer

    @staticmethod
    def _finalize_stream_response(
        thinking_parts: list[str],
        answer_parts: list[str],
    ) -> str:
        """Assemble the final response text from accumulated stream parts.

        Args:
            thinking_parts: Collected thinking-channel text fragments.
            answer_parts: Collected answer-channel text fragments.

        Returns:
            The cleaned final answer, or the thinking text if no answer
            was produced.

        Raises:
            AIProviderError: If both channels are empty.
        """
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

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        """Perform a non-streaming local request with attachment handling.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated analysis text with reasoning blocks removed.

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
            cleaned_attachment_response = _strip_leading_reasoning_blocks(attachment_response)
            if cleaned_attachment_response:
                return cleaned_attachment_response
            return attachment_response.strip()

        prompt_for_completion = self._build_chat_completion_prompt(
            user_prompt=user_prompt,
            attachments=attachments,
        )

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_for_completion},
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

    def _build_chat_completion_prompt(
        self,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
    ) -> str:
        """Build the user prompt, inlining attachments if needed.

        Args:
            user_prompt: The original user-facing prompt text.
            attachments: Optional list of attachment descriptors.

        Returns:
            The prompt string, potentially with attachment data appended.
        """
        prompt_for_completion = user_prompt
        if attachments:
            prompt_for_completion, inlined_attachment_data = _inline_attachment_data_into_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )
            if inlined_attachment_data:
                logger.info("Local attachment fallback inlined attachment data into prompt.")
        return prompt_for_completion

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        """Attempt to send a request with CSV files via the local Responses API.

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
                provider_name="Local provider",
                upload_purpose="assistants",
                convert_csv_to_txt=False,
            )
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

    def get_model_info(self) -> dict[str, str]:
        """Return local provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` and ``"model"`` keys.
        """
        return {"provider": "local", "model": self.model}
