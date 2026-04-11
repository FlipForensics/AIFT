"""Tests for AI provider utility functions.

Covers text extraction helpers (Anthropic/OpenAI), streaming helpers,
attachment normalization, and CSV attachment preparation.
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
    _extract_anthropic_text,
    _extract_openai_text,
)
from app.ai_providers.base import (
    DEFAULT_MAX_TOKENS,
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
    def test_delegates_to_analyze_stream(self) -> None:
        """Default analyze_with_attachments delegates to analyze_stream to avoid recursion."""
        class _ConcreteProvider(AIProvider):
            def analyze(self, system_prompt, user_prompt, max_tokens=DEFAULT_MAX_TOKENS):
                return f"analyzed: {user_prompt}"
            def analyze_stream(self, system_prompt, user_prompt, max_tokens=DEFAULT_MAX_TOKENS):
                yield "chunk1"
                yield "chunk2"
            def get_model_info(self):
                return {"provider": "test", "model": "test"}

        provider = _ConcreteProvider()
        result = provider.analyze_with_attachments("sys", "user", attachments=[{"path": "/x"}])
        self.assertEqual(result, "chunk1chunk2")



if __name__ == "__main__":
    unittest.main()
