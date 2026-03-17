"""Markdown-to-HTML conversion and confidence-token highlighting.

Provides functions for converting AI-produced Markdown (headings, lists, bold,
italic, code spans, tables, fenced code blocks) into safe HTML suitable for
embedding in forensic reports.  Also includes Jinja2 filter wrappers for
direct use in templates.

Key capabilities:

* **Inline formatting** -- bold, italic, backtick code spans.
* **Block elements** -- headings, ordered/unordered lists, fenced code blocks,
  paragraphs with ``<br>`` line breaks.
* **Tables** -- pipe-delimited Markdown tables rendered as ``<table>`` elements.
* **Confidence highlighting** -- severity tokens (``CRITICAL``, ``HIGH``,
  ``MEDIUM``, ``LOW``) wrapped in coloured ``<span>`` elements.

Attributes:
    CONFIDENCE_PATTERN: Regex matching severity tokens (case-insensitive).
    CONFIDENCE_CLASS_MAP: Maps severity label strings to CSS class names.
    MARKDOWN_HEADING_PATTERN: Regex matching ATX-style headings (``#``--``######``).
    MARKDOWN_ORDERED_LIST_PATTERN: Regex matching ordered list items.
    MARKDOWN_UNORDERED_LIST_PATTERN: Regex matching unordered list items.
    MARKDOWN_BOLD_STAR_PATTERN: Regex matching ``**bold**`` syntax.
    MARKDOWN_BOLD_UNDERSCORE_PATTERN: Regex matching ``__bold__`` syntax.
    MARKDOWN_ITALIC_STAR_PATTERN: Regex matching ``*italic*`` syntax.
    MARKDOWN_ITALIC_UNDERSCORE_PATTERN: Regex matching ``_italic_`` syntax.
    MARKDOWN_TABLE_SEPARATOR_CELL_PATTERN: Regex matching table separator cells.
"""

from __future__ import annotations

from collections.abc import Sequence
import html
import re
from typing import Any

from markupsafe import Markup, escape

__all__ = [
    "CONFIDENCE_CLASS_MAP",
    "CONFIDENCE_PATTERN",
    "format_block",
    "format_markdown_block",
    "highlight_confidence_tokens",
    "markdown_to_html",
    "render_inline_markdown",
]

CONFIDENCE_PATTERN = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", re.IGNORECASE)
MARKDOWN_HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
MARKDOWN_ORDERED_LIST_PATTERN = re.compile(r"^\d+\.\s+(.*)$")
MARKDOWN_UNORDERED_LIST_PATTERN = re.compile(r"^[-*]\s+(.*)$")
MARKDOWN_BOLD_STAR_PATTERN = re.compile(r"\*\*(.+?)\*\*")
MARKDOWN_BOLD_UNDERSCORE_PATTERN = re.compile(r"__(.+?)__")
MARKDOWN_ITALIC_STAR_PATTERN = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
MARKDOWN_ITALIC_UNDERSCORE_PATTERN = re.compile(r"(?<!_)_(?!_)(.+?)(?<!_)_(?!_)")
MARKDOWN_TABLE_SEPARATOR_CELL_PATTERN = re.compile(r"^:?-{3,}:?$")

CONFIDENCE_CLASS_MAP = {
    "CRITICAL": "confidence-critical",
    "HIGH": "confidence-high",
    "MEDIUM": "confidence-medium",
    "LOW": "confidence-low",
}


def _stringify(value: Any, default: str = "") -> str:
    """Convert *value* to a stripped string, returning *default* if empty.

    Args:
        value: Any value to convert to string.
        default: Fallback when *value* is None or empty after stripping.

    Returns:
        The stripped string representation, or *default*.
    """
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def highlight_confidence_tokens(text: str) -> str:
    """Wrap severity tokens in coloured ``<span>`` elements.

    Matches ``CRITICAL``, ``HIGH``, ``MEDIUM``, and ``LOW``
    (case-insensitive) and wraps each in a ``<span>`` with the
    corresponding CSS class from :data:`CONFIDENCE_CLASS_MAP`.

    Args:
        text: Pre-escaped HTML string to scan for severity tokens.

    Returns:
        The input string with severity tokens wrapped in spans.
    """
    def _replace_confidence(match: re.Match[str]) -> str:
        """Replace a confidence token match with a styled span."""
        token = match.group(1).upper()
        css_class = CONFIDENCE_CLASS_MAP.get(token, "confidence-unknown")
        return f'<span class="confidence-inline {css_class}">{token}</span>'

    return CONFIDENCE_PATTERN.sub(_replace_confidence, text)


def render_inline_markdown(value: str) -> str:
    """Render inline Markdown formatting to HTML.

    Handles backtick code spans, bold (``**`` and ``__``), italic
    (``*`` and ``_``), and confidence-token highlighting.  Code spans
    are preserved verbatim; all other text is HTML-escaped first.

    Args:
        value: Raw inline Markdown text.

    Returns:
        An HTML string with inline formatting applied.
    """
    source = str(value or "")
    if not source:
        return ""

    parts = re.split(r"(`[^`\n]*`)", source)
    output: list[str] = []
    for part in parts:
        if not part:
            continue
        if part.startswith("`") and part.endswith("`"):
            output.append(f"<code>{part[1:-1]}</code>")
            continue

        escaped = part
        escaped = MARKDOWN_BOLD_STAR_PATTERN.sub(r"<strong>\1</strong>", escaped)
        escaped = MARKDOWN_BOLD_UNDERSCORE_PATTERN.sub(r"<strong>\1</strong>", escaped)
        escaped = MARKDOWN_ITALIC_STAR_PATTERN.sub(r"<em>\1</em>", escaped)
        escaped = MARKDOWN_ITALIC_UNDERSCORE_PATTERN.sub(r"<em>\1</em>", escaped)
        escaped = highlight_confidence_tokens(escaped)
        output.append(escaped)
    return "".join(output)


def _split_table_row(value: str) -> list[str]:
    """Split a Markdown table row into cell strings.

    Strips leading and trailing pipe characters before splitting on
    the remaining pipes.  Returns an empty list when *value* does
    not contain a pipe.

    Args:
        value: A single Markdown table row line.

    Returns:
        A list of stripped cell strings, or an empty list.
    """
    row_text = str(value or "")
    if "|" not in row_text:
        return []

    trimmed = row_text.strip()
    if not trimmed or "|" not in trimmed:
        return []

    if trimmed.startswith("|"):
        trimmed = trimmed[1:]
    if trimmed.endswith("|"):
        trimmed = trimmed[:-1]

    return [cell.strip() for cell in trimmed.split("|")]


def _is_table_separator_row(cells: Sequence[str]) -> bool:
    """Determine whether *cells* represent a Markdown table separator row.

    A separator row consists entirely of cells matching the pattern
    ``:?-+:?`` (e.g. ``---``, ``:---:``, ``---:``).

    Args:
        cells: List of cell strings from a split table row.

    Returns:
        *True* when every cell matches the separator pattern.
    """
    if not cells:
        return False
    return all(MARKDOWN_TABLE_SEPARATOR_CELL_PATTERN.match(str(cell).strip()) for cell in cells)


def _normalize_table_row_cells(cells: Sequence[str], expected_count: int) -> list[str]:
    """Pad or truncate *cells* to exactly *expected_count* entries.

    Cells beyond *expected_count* are discarded; missing cells are
    filled with empty strings.

    Args:
        cells: Raw cell values from a split table row.
        expected_count: The desired number of columns.

    Returns:
        A list of exactly *expected_count* stripped cell strings.
    """
    normalized = [str(cell).strip() for cell in cells[:expected_count]]
    if len(normalized) < expected_count:
        normalized.extend([""] * (expected_count - len(normalized)))
    return normalized


def _render_table_html(header_cells: Sequence[str], body_rows: Sequence[Sequence[str]]) -> str:
    """Render a parsed Markdown table as an HTML ``<table>`` element.

    Each cell value is processed through :func:`render_inline_markdown`
    so that inline formatting (bold, italic, code spans) is preserved.

    Args:
        header_cells: List of header cell strings.
        body_rows: List of body row lists, each containing cell
            strings matching the header column count.

    Returns:
        An HTML string containing the complete ``<table>`` element.
    """
    header_html = "".join(f"<th>{render_inline_markdown(cell)}</th>" for cell in header_cells)
    table_html = [f"<table><thead><tr>{header_html}</tr></thead>"]

    if body_rows:
        rows_html: list[str] = []
        for row in body_rows:
            row_html = "".join(f"<td>{render_inline_markdown(cell)}</td>" for cell in row)
            rows_html.append(f"<tr>{row_html}</tr>")
        table_html.append(f"<tbody>{''.join(rows_html)}</tbody>")

    table_html.append("</table>")
    return "".join(table_html)


def markdown_to_html(value: str) -> str:
    """Convert a complete Markdown text block to HTML.

    Supports headings (``#`` through ``######``), ordered and
    unordered lists, fenced code blocks (triple backticks), tables,
    inline formatting (bold, italic, code spans), and
    confidence-token highlighting.  Paragraphs are wrapped in
    ``<p>`` tags with ``<br>`` line breaks.

    Args:
        value: Raw Markdown text (may contain multiple blocks).

    Returns:
        An HTML string with all recognised Markdown constructs
        converted to their HTML equivalents.
    """
    value = html.escape(str(value))
    lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: list[str] = []
    paragraph_lines: list[str] = []
    list_items: list[str] = []
    list_type = ""
    in_code_fence = False
    code_lines: list[str] = []

    def flush_paragraph() -> None:
        """Flush accumulated paragraph lines into a ``<p>`` block."""
        nonlocal paragraph_lines
        if not paragraph_lines:
            return
        paragraph_text = "\n".join(paragraph_lines)
        rendered = render_inline_markdown(paragraph_text).replace("\n", "<br>\n")
        blocks.append(f"<p>{rendered}</p>")
        paragraph_lines = []

    def flush_list() -> None:
        """Flush accumulated list items into an ``<ol>`` or ``<ul>`` block."""
        nonlocal list_items, list_type
        if not list_items or not list_type:
            list_items = []
            list_type = ""
            return
        items_html = "".join(f"<li>{item}</li>" for item in list_items)
        blocks.append(f"<{list_type}>{items_html}</{list_type}>")
        list_items = []
        list_type = ""

    def flush_code_fence() -> None:
        """Flush accumulated code lines into a ``<pre><code>`` block."""
        nonlocal code_lines
        code_text = "\n".join(code_lines)
        blocks.append(f"<pre><code>{code_text}</code></pre>")
        code_lines = []

    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if in_code_fence:
            if stripped.startswith("```"):
                in_code_fence = False
                flush_code_fence()
            else:
                code_lines.append(line)
            index += 1
            continue

        if stripped.startswith("```"):
            flush_paragraph()
            flush_list()
            in_code_fence = True
            code_lines = []
            index += 1
            continue

        if not stripped:
            flush_paragraph()
            flush_list()
            index += 1
            continue

        header_cells = _split_table_row(line)
        if header_cells and index + 1 < len(lines):
            separator_cells = _split_table_row(lines[index + 1])
            if (
                separator_cells
                and len(header_cells) == len(separator_cells)
                and _is_table_separator_row(separator_cells)
            ):
                flush_paragraph()
                flush_list()

                expected_columns = len(header_cells)
                normalized_header = _normalize_table_row_cells(header_cells, expected_columns)
                body_rows: list[list[str]] = []

                index += 2
                while index < len(lines):
                    body_line = lines[index]
                    body_stripped = body_line.strip()
                    if not body_stripped:
                        break

                    parsed_cells = _split_table_row(body_line)
                    if not parsed_cells:
                        break

                    body_rows.append(_normalize_table_row_cells(parsed_cells, expected_columns))
                    index += 1

                blocks.append(_render_table_html(normalized_header, body_rows))
                continue

        heading_match = MARKDOWN_HEADING_PATTERN.match(stripped)
        if heading_match:
            flush_paragraph()
            flush_list()
            level = len(heading_match.group(1))
            heading_text = render_inline_markdown(heading_match.group(2))
            blocks.append(f"<h{level}>{heading_text}</h{level}>")
            index += 1
            continue

        ordered_match = MARKDOWN_ORDERED_LIST_PATTERN.match(stripped)
        if ordered_match:
            flush_paragraph()
            if list_type != "ol":
                flush_list()
                list_type = "ol"
                list_items = []
            list_items.append(render_inline_markdown(ordered_match.group(1)))
            index += 1
            continue

        unordered_match = MARKDOWN_UNORDERED_LIST_PATTERN.match(stripped)
        if unordered_match:
            flush_paragraph()
            if list_type != "ul":
                flush_list()
                list_type = "ul"
                list_items = []
            list_items.append(render_inline_markdown(unordered_match.group(1)))
            index += 1
            continue

        flush_list()
        paragraph_lines.append(line.strip())
        index += 1

    if in_code_fence:
        flush_code_fence()
    flush_paragraph()
    flush_list()

    return "\n".join(blocks)


def format_block(value: Any) -> Markup:
    """Escape plain text and convert it to safe HTML with line breaks.

    Applies confidence-token highlighting (CRITICAL, HIGH, etc.)
    and replaces newline characters with ``<br>`` tags.  Intended for
    use as a Jinja2 template filter.

    Args:
        value: Raw text to format.

    Returns:
        A :class:`~markupsafe.Markup` string safe for Jinja2
        rendering, or an N/A placeholder when *value* is empty.
    """
    text = _stringify(value, default="")
    if not text:
        return Markup('<span class="empty-value">N/A</span>')

    escaped = str(escape(text.replace("\r\n", "\n").replace("\r", "\n")))
    highlighted = highlight_confidence_tokens(escaped)
    with_line_breaks = highlighted.replace("\n", "<br>\n")
    return Markup(with_line_breaks)


def format_markdown_block(value: Any) -> Markup:
    """Convert Markdown text to HTML via :func:`markdown_to_html`.

    Intended for use as a Jinja2 template filter.

    Args:
        value: Raw Markdown text to render.

    Returns:
        A :class:`~markupsafe.Markup` string of rendered HTML, or
        an N/A placeholder when *value* is empty.
    """
    text = _stringify(value, default="")
    if not text:
        return Markup('<span class="empty-value">N/A</span>')
    return Markup(markdown_to_html(text))
