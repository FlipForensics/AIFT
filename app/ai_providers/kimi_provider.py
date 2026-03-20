"""Moonshot Kimi API provider implementation.

Uses the ``openai`` Python SDK pointed at the Moonshot Kimi API base URL.
Supports synchronous and streaming generation, CSV file attachments via
the Responses API, and automatic model-alias mapping for deprecated Kimi
model identifiers.

Attributes:
    logger: Module-level logger for Kimi provider operations.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterator, Mapping

from .base import (
    AIProvider,
    AIProviderError,
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_KIMI_BASE_URL,
    DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
    DEFAULT_KIMI_MODEL,
    DEFAULT_MAX_TOKENS,
    _is_attachment_unsupported_error,
    _is_context_length_error,
    _is_kimi_model_not_available_error,
    _normalize_api_key_value,
    _normalize_kimi_model_name,
    _normalize_openai_compatible_base_url,
    _resolve_timeout_seconds,
    _run_with_rate_limit_retries,
    _T,
)
from .utils import (
    _extract_openai_delta_text,
    _extract_openai_text,
    _inline_attachment_data_into_prompt,
    upload_and_request_via_responses_api,
)

logger = logging.getLogger(__name__)


class KimiProvider(AIProvider):
    """Moonshot Kimi API provider implementation.

    Attributes:
        api_key (str): The Moonshot/Kimi API key.
        model (str): The Kimi model identifier.
        base_url (str): The normalized Kimi API base URL.
        attach_csv_as_file (bool): Whether to upload CSV artifacts as
            file attachments.
        request_timeout_seconds (float): HTTP timeout in seconds.
        client: The ``openai.OpenAI`` SDK client instance configured for Kimi.
    """

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_KIMI_MODEL,
        base_url: str = DEFAULT_KIMI_BASE_URL,
        attach_csv_as_file: bool = True,
        request_timeout_seconds: float = DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the Kimi provider.

        Args:
            api_key: Moonshot/Kimi API key. Must be non-empty.
            model: Kimi model identifier. Deprecated aliases are mapped.
            base_url: Kimi API base URL.
            attach_csv_as_file: If ``True``, attempt file uploads.
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
                "Kimi API key is not configured. "
                "Set `ai.kimi.api_key` in config.yaml or the MOONSHOT_API_KEY environment variable."
            )

        self._openai = openai
        self.api_key = normalized_api_key
        self.model = _normalize_kimi_model_name(model)
        self.base_url = _normalize_openai_compatible_base_url(
            base_url=base_url,
            default_base_url=DEFAULT_KIMI_BASE_URL,
        )
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.request_timeout_seconds = _resolve_timeout_seconds(
            request_timeout_seconds,
            DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
        )
        self.client = openai.OpenAI(
            api_key=normalized_api_key,
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
        )
        logger.info("Initialized Kimi provider at %s with model %s (timeout %.1fs)", self.base_url, self.model, self.request_timeout_seconds)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to Kimi and return the generated text.

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
        """Stream generated text chunks from Kimi.

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
            stream = self._run_kimi_request(
                lambda: self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    stream=True,
                )
            )
            emitted = False
            try:
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

            if not emitted:
                raise AIProviderError("Kimi returned an empty response.")

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via the Kimi Responses API.

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

        return self._run_kimi_request(_request)

    def _run_kimi_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute a Kimi request with rate-limit retries and error mapping.

        Args:
            request_fn: A zero-argument callable that performs the request.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On any OpenAI SDK error (with Kimi messages).
        """
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
        """Perform a non-streaming Kimi request with attachment handling.

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
            prompt_for_completion, inlined = _inline_attachment_data_into_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )
            if inlined:
                logger.info("Kimi attachment fallback inlined attachment data into prompt.")

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_for_completion},
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
        """Attempt to send a request with CSV files via the Kimi Responses API.

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
                provider_name="Kimi",
                upload_purpose=DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
                convert_csv_to_txt=False,
            )
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

    def get_model_info(self) -> dict[str, str]:
        """Return Kimi provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` and ``"model"`` keys.
        """
        return {"provider": "kimi", "model": self.model}
