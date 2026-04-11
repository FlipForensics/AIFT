"""Text extraction, attachment handling, and response processing utilities.

This module contains all functions for extracting text from AI provider
responses (Anthropic and OpenAI formats), normalizing and inlining file
attachments, stripping reasoning blocks from local model output, and
shared Responses API file-upload logic used by OpenAI, Kimi, and Local
providers.

Attributes:
    _LEADING_REASONING_BLOCK_RE: Regex pattern matching leading ``<think>``,
        ``<thinking>``, ``<reasoning>`` XML blocks or fenced code blocks.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger(__name__)

_LEADING_REASONING_BLOCK_RE = re.compile(
    r"^\s*(?:"
    r"(?:<\s*(?:think|thinking|reasoning)\b[^>]*>.*?<\s*/\s*(?:think|thinking|reasoning)\s*>\s*)"
    r"|(?:```(?:think|thinking|reasoning)[^\n]*\n.*?```\s*)"
    r")+",
    flags=re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# Anthropic text extraction
# ---------------------------------------------------------------------------


def _extract_anthropic_text(response: Any) -> str:
    """Extract the concatenated text from an Anthropic Messages API response.

    Iterates over content blocks in the response, collecting text from
    both object-style blocks (with a ``.text`` attribute) and dict-style
    blocks (with a ``"text"`` key).

    Args:
        response: The Anthropic ``Message`` response object.

    Returns:
        The joined text content, stripped of whitespace.
    """
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


def _extract_anthropic_stream_text(event: Any) -> str:
    """Extract text deltas from Anthropic streamed events.

    Handles ``content_block_delta``, ``content_block_start``, and generic
    delta events from the Anthropic streaming API.

    Args:
        event: A single streamed event from the Anthropic Messages API.

    Returns:
        The text delta string, or empty string if no text content.
    """
    if event is None:
        return ""

    event_type = getattr(event, "type", None)
    if event_type is None and isinstance(event, dict):
        event_type = event.get("type")

    if event_type == "content_block_delta":
        delta = getattr(event, "delta", None)
        if delta is None and isinstance(event, dict):
            delta = event.get("delta")
        text = getattr(delta, "text", None)
        if text is None and isinstance(delta, dict):
            text = delta.get("text")
        if isinstance(text, str):
            return text

    if event_type == "content_block_start":
        content_block = getattr(event, "content_block", None)
        if content_block is None and isinstance(event, dict):
            content_block = event.get("content_block")
        text = getattr(content_block, "text", None)
        if text is None and isinstance(content_block, dict):
            text = content_block.get("text")
        if isinstance(text, str):
            return text

    delta = getattr(event, "delta", None)
    if delta is None and isinstance(event, dict):
        delta = event.get("delta")
    if delta is not None:
        text = getattr(delta, "text", None)
        if text is None and isinstance(delta, dict):
            text = delta.get("text")
        if isinstance(text, str):
            return text

    return ""


# ---------------------------------------------------------------------------
# OpenAI text extraction
# ---------------------------------------------------------------------------


def _coerce_openai_text(value: Any) -> str:
    """Normalize OpenAI-compatible response text payloads into plain strings.

    Handles string values, lists of text items (objects or dicts), and
    returns an empty string for unsupported types.

    Args:
        value: A text value from an OpenAI-compatible response.

    Returns:
        The concatenated plain text string.
    """
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


def _extract_openai_text(response: Any) -> str:
    """Extract the generated text from an OpenAI Chat Completions API response.

    Handles plain string content, structured content arrays, and
    reasoning-model fallback fields (``reasoning_content``, ``reasoning``).
    If the model refused the request (non-empty ``refusal`` field), raises
    an ``AIProviderError`` instead of returning the refusal as valid output.

    Args:
        response: The OpenAI ``ChatCompletion`` response object.

    Returns:
        The extracted text content, stripped of whitespace.

    Raises:
        AIProviderError: If the model's ``refusal`` field is non-empty,
            indicating it declined to answer the request.
    """
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

    # Check for model refusal before falling back to reasoning fields.
    # The ``refusal`` field is set by OpenAI when the model declines a
    # request.  Returning refusal text as valid analysis output would cause
    # it to appear in forensic reports, so raise an error instead.
    refusal_value = getattr(message, "refusal", None)
    if refusal_value is None and isinstance(message, dict):
        refusal_value = message.get("refusal")
    refusal_text = _coerce_openai_text(refusal_value).strip()
    if refusal_text:
        from .base import AIProviderError

        raise AIProviderError(f"AI model refused the request: {refusal_text}")

    for field_name in ("reasoning_content", "reasoning"):
        field_value = getattr(message, field_name, None)
        if field_value is None and isinstance(message, dict):
            field_value = message.get(field_name)
        text = _coerce_openai_text(field_value)
        stripped = text.strip()
        if stripped:
            return stripped

    return ""


def _extract_openai_delta_text(delta: Any, field_names: tuple[str, ...]) -> str:
    """Extract streaming delta text for one of the requested fields.

    Args:
        delta: The streaming chunk delta object or dict.
        field_names: Tuple of field names to check in priority order.

    Returns:
        The first non-empty text value found, or empty string.
    """
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


def _extract_openai_responses_text(response: Any) -> str:
    """Extract output text from OpenAI Responses API payloads.

    First attempts the ``output_text`` attribute, then falls back to
    iterating over structured output items.

    Args:
        response: The OpenAI Responses API response object or dict.

    Returns:
        The extracted and stripped text content.
    """
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


# ---------------------------------------------------------------------------
# Reasoning block handling
# ---------------------------------------------------------------------------


def _strip_leading_reasoning_blocks(text: str) -> str:
    """Remove leading model-thinking blocks from OpenAI-compatible output.

    Some local reasoning models emit ``<think>`` or ``<reasoning>`` blocks
    at the start of their output. This strips those blocks.

    Args:
        text: Raw model output that may begin with reasoning blocks.

    Returns:
        The text with leading reasoning blocks removed.
    """
    value = str(text or "").strip()
    if not value:
        return ""
    return _LEADING_REASONING_BLOCK_RE.sub("", value, count=1).strip()


def _clean_streamed_answer_text(answer_text: str, thinking_text: str) -> str:
    """Drop duplicated streamed thinking text from the final answer channel.

    Args:
        answer_text: The accumulated answer-channel text from streaming.
        thinking_text: The accumulated thinking-channel text from streaming.

    Returns:
        The cleaned answer text with duplicated reasoning removed.
    """
    answer = str(answer_text or "").strip()
    if not answer:
        return ""

    thinking = str(thinking_text or "").strip()
    if thinking and len(thinking) >= 24 and answer.startswith(thinking):
        answer = answer[len(thinking) :].lstrip()

    return _strip_leading_reasoning_blocks(answer)


# ---------------------------------------------------------------------------
# Attachment normalization
# ---------------------------------------------------------------------------


def normalize_attachment_input(attachment: Mapping[str, str] | Any) -> dict[str, str] | None:
    """Validate and normalize a single attachment descriptor.

    Args:
        attachment: A raw attachment descriptor with at least a ``"path"`` key.

    Returns:
        A normalized dict with ``"path"``, ``"name"``, ``"mime_type"`` keys,
        or ``None`` if invalid.
    """
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


def normalize_attachment_inputs(
    attachments: list[Mapping[str, str]] | None,
) -> list[dict[str, str]]:
    """Validate and normalize a list of attachment descriptors.

    Args:
        attachments: Optional list of raw attachment descriptors.

    Returns:
        A list of validated attachment dicts. May be empty.
    """
    normalized: list[dict[str, str]] = []
    for attachment in attachments or []:
        candidate = normalize_attachment_input(attachment)
        if candidate is not None:
            normalized.append(candidate)
    return normalized


def _prepare_openai_attachment_upload(attachment: Mapping[str, str]) -> tuple[str, str, bool]:
    """Normalize OpenAI attachment upload metadata.

    Some OpenAI Responses API models reject ``.csv`` file extensions.
    This converts CSV metadata to TXT format while keeping contents unchanged.

    Args:
        attachment: A normalized attachment descriptor.

    Returns:
        A 3-tuple of ``(upload_name, upload_mime_type, was_converted)``.
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
    """Append attachment file contents to the user prompt for text-only fallback.

    All attachment data is inlined without truncation -- in DFIR, every row
    matters. When the resulting prompt is too large, the caller uses chunked
    analysis to split it.

    Args:
        user_prompt: The original user prompt text.
        attachments: Optional list of attachment descriptors.

    Returns:
        A 2-tuple of ``(modified_prompt, was_inlined)``.
    """
    normalized_attachments = normalize_attachment_inputs(attachments)
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


def upload_and_request_via_responses_api(
    client: Any,
    openai_module: Any,
    model: str,
    normalized_attachments: list[dict[str, str]],
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    provider_name: str,
    upload_purpose: str = "assistants",
    convert_csv_to_txt: bool = False,
) -> str:
    """Upload attachments and make a Responses API request.

    This is the shared implementation for file-attachment mode used by
    OpenAI, Kimi, and Local providers. Uploads each attachment as a file,
    builds a Responses API request with ``input_file`` references, extracts
    the output text, and cleans up uploaded files.

    Args:
        client: The ``openai.OpenAI`` SDK client instance.
        openai_module: The ``openai`` module (for exception types).
        model: The model identifier to use for the Responses API request.
        normalized_attachments: Validated attachment descriptors.
        system_prompt: The system-level instruction text.
        user_prompt: The user-facing prompt text.
        max_tokens: Maximum completion tokens.
        provider_name: Human-readable provider name for error messages.
        upload_purpose: The ``purpose`` parameter for file uploads.
        convert_csv_to_txt: If ``True``, convert CSV file metadata to TXT
            format before uploading (used by OpenAI).

    Returns:
        The generated text from the Responses API.

    Raises:
        AIProviderError: If the response is empty or file upload fails.
    """
    from .base import AIProviderError, _resolve_completion_token_retry_limit

    uploaded_file_ids: list[str] = []
    try:
        for attachment in normalized_attachments:
            attachment_path = Path(attachment["path"])

            if convert_csv_to_txt:
                upload_name, upload_mime_type, converted = _prepare_openai_attachment_upload(attachment)
                if converted:
                    logger.debug(
                        "Converting %s attachment upload from CSV to TXT: %s -> %s",
                        provider_name,
                        attachment.get("name", attachment_path.name),
                        upload_name,
                    )
            else:
                upload_name = attachment["name"]
                upload_mime_type = attachment["mime_type"]

            with attachment_path.open("rb") as handle:
                uploaded = client.files.create(
                    file=(upload_name, handle.read(), upload_mime_type),
                    purpose=upload_purpose,
                )

            file_id = getattr(uploaded, "id", None)
            if file_id is None and isinstance(uploaded, dict):
                file_id = uploaded.get("id")
            if not isinstance(file_id, str) or not file_id.strip():
                raise AIProviderError(f"{provider_name} file upload returned no file id.")
            uploaded_file_ids.append(file_id)

        user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
        for file_id in uploaded_file_ids:
            user_content.append({"type": "input_file", "file_id": file_id})

        response_request: dict[str, Any] = {
            "model": model,
            "input": [
                {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                {"role": "user", "content": user_content},
            ],
            "max_output_tokens": max_tokens,
        }

        try:
            response = client.responses.create(**response_request)
        except openai_module.BadRequestError as error:
            retry_token_count = _resolve_completion_token_retry_limit(
                error=error,
                requested_tokens=max_tokens,
            )
            if retry_token_count is None:
                raise
            logger.warning(
                "%s rejected max_output_tokens=%d; retrying with max_output_tokens=%d.",
                provider_name,
                max_tokens,
                retry_token_count,
            )
            response_request["max_output_tokens"] = retry_token_count
            response = client.responses.create(**response_request)

        text = _extract_openai_responses_text(response)
        if not text:
            raise AIProviderError(
                f"{provider_name} returned an empty response for file-attachment mode."
            )
        return text
    finally:
        for uploaded_file_id in uploaded_file_ids:
            try:
                client.files.delete(uploaded_file_id)
            except Exception:
                continue
