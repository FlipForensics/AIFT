"""HTML report generation utilities."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

DEFAULT_CASE_NAME = "Untitled Investigation"
DEFAULT_TOOL_VERSION = "unknown"
DEFAULT_AI_PROVIDER = "unknown"
LOGO_FILE_CANDIDATES = (
    "AIFT Logo - White Text.png",
    "AIFT Logo - Dark Text.png",
    "AIFT Logo Wide.png",
    "AIFT_Logo.png",
    "AIFt_Logo_Transparent.png",
    "AIFT_Logo_Transparent.png",
)

CONFIDENCE_PATTERN = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", re.IGNORECASE)
MARKDOWN_HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
MARKDOWN_ORDERED_LIST_PATTERN = re.compile(r"^\d+\.\s+(.*)$")
MARKDOWN_UNORDERED_LIST_PATTERN = re.compile(r"^[-*]\s+(.*)$")
MARKDOWN_BOLD_STAR_PATTERN = re.compile(r"\*\*(.+?)\*\*")
MARKDOWN_BOLD_UNDERSCORE_PATTERN = re.compile(r"__(.+?)__")
MARKDOWN_ITALIC_STAR_PATTERN = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
MARKDOWN_ITALIC_UNDERSCORE_PATTERN = re.compile(r"(?<!_)_(?!_)(.+?)(?<!_)_(?!_)")
SAFE_CASE_ID_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")

CONFIDENCE_CLASS_MAP = {
    "CRITICAL": "confidence-critical",
    "HIGH": "confidence-high",
    "MEDIUM": "confidence-medium",
    "LOW": "confidence-low",
}


class ReportGenerator:
    """Render investigation results into a standalone HTML report."""

    def __init__(
        self,
        templates_dir: str | Path | None = None,
        cases_root: str | Path | None = None,
        template_name: str = "report_template.html",
    ) -> None:
        project_root = Path(__file__).resolve().parents[1]
        self.templates_dir = Path(templates_dir) if templates_dir is not None else project_root / "templates"
        self.cases_root = Path(cases_root) if cases_root is not None else project_root / "cases"

        self.environment = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.environment.filters["format_block"] = self._format_block
        self.environment.filters["format_markdown_block"] = self._format_markdown_block
        self.template = self.environment.get_template(template_name)

    def generate(
        self,
        analysis_results: dict[str, Any],
        image_metadata: dict[str, Any],
        evidence_hashes: dict[str, Any],
        investigation_context: str,
        audit_log_entries: list[dict[str, Any]],
    ) -> Path:
        """Generate a standalone HTML report and return the created file path."""
        analysis = dict(analysis_results or {})
        metadata = dict(image_metadata or {})
        hashes = dict(evidence_hashes or {})
        audit_entries = self._normalize_audit_entries(audit_log_entries)

        case_id = self._resolve_case_id(analysis, metadata, hashes)
        case_name = self._resolve_case_name(analysis)
        generated_at = datetime.now(timezone.utc)
        generated_iso = generated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
        report_timestamp = generated_at.strftime("%Y%m%d_%H%M%S")

        summary_text = self._stringify(analysis.get("summary"))
        executive_summary = self._stringify(analysis.get("executive_summary") or summary_text)

        per_artifact = self._normalize_per_artifact_findings(analysis)
        evidence_summary = self._build_evidence_summary(metadata, hashes)
        hash_verification = self._resolve_hash_verification(hashes)

        render_context = {
            "case_name": case_name,
            "case_id": case_id,
            "generated_at": generated_iso,
            "tool_version": self._resolve_tool_version(analysis, audit_entries),
            "ai_provider": self._resolve_ai_provider(analysis),
            "logo_data_uri": self._resolve_logo_data_uri(),
            "evidence": evidence_summary,
            "hash_verification": hash_verification,
            "investigation_context": self._stringify(investigation_context, default="No investigation context provided."),
            "executive_summary": executive_summary,
            "per_artifact_findings": per_artifact,
            "audit_entries": audit_entries,
        }

        rendered = self.template.render(**render_context)

        report_dir = self.cases_root / case_id / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"report_{report_timestamp}.html"
        report_path.write_text(rendered, encoding="utf-8")
        return report_path

    def _resolve_logo_data_uri(self) -> str:
        project_root = Path(__file__).resolve().parents[1]
        images_dir = project_root / "images"
        if not images_dir.is_dir():
            return ""

        for filename in LOGO_FILE_CANDIDATES:
            candidate = images_dir / filename
            if candidate.is_file():
                return self._file_to_data_uri(candidate)

        fallback_images = sorted(
            path
            for path in images_dir.iterdir()
            if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".svg"}
        )
        if fallback_images:
            return self._file_to_data_uri(fallback_images[0])

        return ""

    @staticmethod
    def _file_to_data_uri(path: Path) -> str:
        mime_types = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
            ".svg": "image/svg+xml",
        }
        mime = mime_types.get(path.suffix.lower(), "application/octet-stream")
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:{mime};base64,{encoded}"

    def _resolve_case_id(
        self,
        analysis: Mapping[str, Any],
        metadata: Mapping[str, Any],
        hashes: Mapping[str, Any],
    ) -> str:
        candidates = [
            analysis.get("case_id"),
            analysis.get("id"),
            hashes.get("case_id"),
            metadata.get("case_id"),
        ]

        nested_case = analysis.get("case")
        if isinstance(nested_case, Mapping):
            candidates.extend([nested_case.get("id"), nested_case.get("case_id")])

        for candidate in candidates:
            value = self._stringify(candidate, default="")
            if value:
                safe = SAFE_CASE_ID_PATTERN.sub("_", value).strip("_")
                if safe:
                    return safe

        raise ValueError("Unable to determine case identifier for report generation.")

    def _resolve_case_name(self, analysis: Mapping[str, Any]) -> str:
        nested_case = analysis.get("case")
        if isinstance(nested_case, Mapping):
            nested_name = self._stringify(nested_case.get("name"), default="")
            if nested_name:
                return nested_name

        return self._stringify(analysis.get("case_name"), default=DEFAULT_CASE_NAME)

    def _resolve_tool_version(
        self,
        analysis: Mapping[str, Any],
        audit_entries: list[dict[str, str]],
    ) -> str:
        explicit_version = self._stringify(analysis.get("tool_version"), default="")
        if explicit_version:
            return explicit_version

        for entry in reversed(audit_entries):
            version = self._stringify(entry.get("tool_version"), default="")
            if version:
                return version

        return DEFAULT_TOOL_VERSION

    def _resolve_ai_provider(self, analysis: Mapping[str, Any]) -> str:
        explicit = self._stringify(analysis.get("ai_provider"), default="")
        if explicit:
            return explicit

        model_info = analysis.get("model_info")
        if isinstance(model_info, Mapping):
            provider = self._stringify(model_info.get("provider"), default=DEFAULT_AI_PROVIDER)
            model = self._stringify(model_info.get("model"), default="")
            if model:
                return f"{provider} ({model})"
            return provider

        return DEFAULT_AI_PROVIDER

    def _build_evidence_summary(
        self,
        metadata: Mapping[str, Any],
        hashes: Mapping[str, Any],
    ) -> dict[str, str]:
        hostname = self._stringify(metadata.get("hostname"), default="Unknown")
        os_value = self._stringify(metadata.get("os_version") or metadata.get("os"), default="Unknown")
        domain = self._stringify(metadata.get("domain"), default="Unknown")
        ips = self._stringify_ips(metadata.get("ips") or metadata.get("ip_addresses") or metadata.get("ip"))

        size_value = hashes.get("size_bytes")
        if size_value is None:
            size_value = hashes.get("file_size_bytes")

        return {
            "filename": self._stringify(
                hashes.get("filename") or hashes.get("file_name") or metadata.get("filename"),
                default="Unknown",
            ),
            "sha256": self._stringify(hashes.get("sha256"), default="N/A"),
            "md5": self._stringify(hashes.get("md5"), default="N/A"),
            "file_size": self._format_file_size(size_value),
            "hostname": hostname,
            "os_version": os_value,
            "domain": domain,
            "ips": ips,
        }

    def _resolve_hash_verification(self, hashes: Mapping[str, Any]) -> dict[str, str | bool]:
        explicit = hashes.get("hash_verified")
        if explicit is None:
            explicit = hashes.get("verification_passed")
        if explicit is None:
            explicit = hashes.get("verified")

        if isinstance(explicit, bool):
            passed = explicit
            detail = "Hash verification explicitly reported by workflow."
            return {"passed": passed, "label": "PASS" if passed else "FAIL", "detail": detail}
        if isinstance(explicit, str):
            normalized_explicit = explicit.strip().lower()
            if normalized_explicit in {"true", "pass", "passed", "ok", "yes"}:
                return {
                    "passed": True,
                    "label": "PASS",
                    "detail": "Hash verification explicitly reported by workflow.",
                }
            if normalized_explicit in {"false", "fail", "failed", "no"}:
                return {
                    "passed": False,
                    "label": "FAIL",
                    "detail": "Hash verification explicitly reported by workflow.",
                }

        expected = self._stringify(
            hashes.get("expected_sha256") or hashes.get("intake_sha256") or hashes.get("original_sha256"),
            default="",
        ).lower()
        observed = self._stringify(
            hashes.get("reverified_sha256") or hashes.get("current_sha256") or hashes.get("computed_sha256"),
            default="",
        ).lower()

        if expected and observed:
            passed = expected == observed
            detail = "Re-verified SHA-256 matches intake hash." if passed else "Re-verified SHA-256 does not match intake hash."
            return {"passed": passed, "label": "PASS" if passed else "FAIL", "detail": detail}

        return {
            "passed": False,
            "label": "FAIL",
            "detail": "Insufficient data to validate hash integrity.",
        }

    def _normalize_per_artifact_findings(self, analysis: Mapping[str, Any]) -> list[dict[str, Any]]:
        raw_findings = analysis.get("per_artifact")
        if raw_findings is None:
            raw_findings = analysis.get("per_artifact_findings")

        findings: list[dict[str, Any]] = []
        iterable = self._coerce_per_artifact_iterable(raw_findings)

        for index, finding in enumerate(iterable, start=1):
            if not isinstance(finding, Mapping):
                continue

            artifact_name = self._stringify(
                finding.get("artifact_name") or finding.get("name") or finding.get("artifact_key"),
                default=f"Artifact {index}",
            )
            artifact_key = self._stringify(finding.get("artifact_key"), default="")
            analysis_text = self._stringify(
                finding.get("analysis") or finding.get("findings") or finding.get("text"),
                default="No findings were provided.",
            )
            confidence_label, confidence_class = self._resolve_confidence(
                self._stringify(finding.get("confidence"), default=""),
                analysis_text,
            )

            time_range_start = self._stringify(
                finding.get("time_range_start") or self._nested_lookup(finding, ("time_range", "start")),
                default="N/A",
            )
            time_range_end = self._stringify(
                finding.get("time_range_end") or self._nested_lookup(finding, ("time_range", "end")),
                default="N/A",
            )
            record_count = self._stringify(finding.get("record_count"), default="N/A")
            key_data_points = self._normalize_key_data_points(
                finding.get("key_data_points") or finding.get("key_points") or finding.get("data_points")
            )

            findings.append(
                {
                    "artifact_name": artifact_name,
                    "artifact_key": artifact_key,
                    "analysis": analysis_text,
                    "record_count": record_count,
                    "time_range_start": time_range_start,
                    "time_range_end": time_range_end,
                    "key_data_points": key_data_points,
                    "confidence_label": confidence_label,
                    "confidence_class": confidence_class,
                }
            )

        return findings

    def _coerce_per_artifact_iterable(self, raw_findings: Any) -> Sequence[Any]:
        if isinstance(raw_findings, Sequence) and not isinstance(raw_findings, (str, bytes, bytearray)):
            return raw_findings

        if isinstance(raw_findings, Mapping):
            if self._looks_like_single_finding(raw_findings):
                return [raw_findings]

            coerced: list[dict[str, Any]] = []
            for artifact_key, raw_value in raw_findings.items():
                if isinstance(raw_value, Mapping):
                    merged = dict(raw_value)
                    merged.setdefault("artifact_key", self._stringify(artifact_key, default=""))
                    if not self._stringify(merged.get("artifact_name"), default=""):
                        merged["artifact_name"] = self._stringify(artifact_key, default="Unknown Artifact")
                    coerced.append(merged)
                    continue

                analysis_text = self._stringify(raw_value, default="")
                if not analysis_text:
                    continue
                artifact_label = self._stringify(artifact_key, default="Unknown Artifact")
                coerced.append(
                    {
                        "artifact_key": artifact_label,
                        "artifact_name": artifact_label,
                        "analysis": analysis_text,
                    }
                )
            return coerced

        return []

    @staticmethod
    def _looks_like_single_finding(value: Mapping[str, Any]) -> bool:
        finding_keys = {
            "artifact_name",
            "name",
            "artifact_key",
            "analysis",
            "findings",
            "text",
            "record_count",
            "time_range_start",
            "time_range_end",
            "time_range",
            "key_data_points",
            "key_points",
            "data_points",
            "confidence",
        }
        return any(key in value for key in finding_keys)

    def _normalize_key_data_points(self, raw_points: Any) -> list[dict[str, str]]:
        if isinstance(raw_points, Sequence) and not isinstance(raw_points, (str, bytes, bytearray)):
            points: list[dict[str, str]] = []
            for point in raw_points:
                if isinstance(point, Mapping):
                    timestamp = self._stringify(
                        point.get("timestamp") or point.get("time") or point.get("date") or point.get("ts"),
                        default="",
                    )
                    value = self._stringify(
                        point.get("value") or point.get("data") or point.get("detail") or point.get("event"),
                        default="",
                    )
                    if not value:
                        value = self._mapping_to_kv_text(point)
                    points.append({"timestamp": timestamp, "value": value})
                else:
                    text_value = self._stringify(point, default="")
                    if text_value:
                        points.append({"timestamp": "", "value": text_value})
            return points

        if isinstance(raw_points, Mapping):
            return [{"timestamp": "", "value": self._mapping_to_kv_text(raw_points)}]

        if raw_points is None:
            return []

        text_value = self._stringify(raw_points, default="")
        if text_value:
            return [{"timestamp": "", "value": text_value}]
        return []

    def _normalize_audit_entries(self, entries: Sequence[Any] | None) -> list[dict[str, str]]:
        if entries is None:
            return []

        normalized: list[dict[str, str]] = []
        for entry in entries:
            mapping = self._coerce_mapping(entry)
            if mapping is None:
                continue

            details_value = mapping.get("details")
            if isinstance(details_value, Mapping):
                details_text = json.dumps(details_value, sort_keys=True, separators=(",", ": "))
            elif isinstance(details_value, Sequence) and not isinstance(details_value, (str, bytes, bytearray)):
                details_text = json.dumps(list(details_value), separators=(",", ": "))
            else:
                details_text = self._stringify(details_value, default="")

            normalized.append(
                {
                    "timestamp": self._stringify(mapping.get("timestamp"), default="N/A"),
                    "action": self._stringify(mapping.get("action"), default="unknown"),
                    "details": details_text,
                    "tool_version": self._stringify(mapping.get("tool_version"), default=""),
                }
            )

        return normalized

    @staticmethod
    def _resolve_confidence(explicit_value: str, analysis_text: str) -> tuple[str, str]:
        if explicit_value:
            label = explicit_value.strip().upper()
            if label in CONFIDENCE_CLASS_MAP:
                return label, CONFIDENCE_CLASS_MAP[label]

        match = CONFIDENCE_PATTERN.search(analysis_text or "")
        if match:
            label = match.group(1).upper()
            return label, CONFIDENCE_CLASS_MAP[label]

        return "UNSPECIFIED", "confidence-unknown"

    @staticmethod
    def _nested_lookup(mapping: Mapping[str, Any], path: tuple[str, str]) -> Any:
        current: Any = mapping
        for key in path:
            if not isinstance(current, Mapping):
                return None
            current = current.get(key)
        return current

    @staticmethod
    def _coerce_mapping(value: Any) -> dict[str, Any] | None:
        if isinstance(value, Mapping):
            return dict(value)
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            if isinstance(parsed, Mapping):
                return dict(parsed)
        return None

    @staticmethod
    def _format_file_size(size_value: Any) -> str:
        if size_value is None:
            return "N/A"

        try:
            size = int(size_value)
        except (TypeError, ValueError):
            return str(size_value)

        units = ["B", "KB", "MB", "GB", "TB"]
        working = float(size)
        unit = units[0]
        for candidate in units:
            unit = candidate
            if working < 1024.0 or candidate == units[-1]:
                break
            working /= 1024.0

        if unit == "B":
            return f"{int(working)} {unit}"
        return f"{working:.2f} {unit} ({size} bytes)"

    @staticmethod
    def _stringify_ips(value: Any) -> str:
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            cleaned = [str(item).strip() for item in value if str(item).strip()]
            return ", ".join(cleaned) if cleaned else "Unknown"

        text = str(value).strip() if value is not None else ""
        return text or "Unknown"

    @staticmethod
    def _mapping_to_kv_text(value: Mapping[str, Any]) -> str:
        parts = [
            f"{str(key)}={str(item)}"
            for key, item in value.items()
            if item not in (None, "")
        ]
        return "; ".join(parts)

    @staticmethod
    def _stringify(value: Any, default: str = "") -> str:
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default

    @staticmethod
    def _format_block(value: Any) -> Markup:
        text = ReportGenerator._stringify(value, default="")
        if not text:
            return Markup('<span class="empty-value">N/A</span>')

        escaped = str(escape(text.replace("\r\n", "\n").replace("\r", "\n")))
        highlighted = ReportGenerator._highlight_confidence_tokens(escaped)
        with_line_breaks = highlighted.replace("\n", "<br>\n")
        return Markup(with_line_breaks)

    @staticmethod
    def _format_markdown_block(value: Any) -> Markup:
        text = ReportGenerator._stringify(value, default="")
        if not text:
            return Markup('<span class="empty-value">N/A</span>')
        return Markup(ReportGenerator._markdown_to_html(text))

    @staticmethod
    def _highlight_confidence_tokens(text: str) -> str:
        def _replace_confidence(match: re.Match[str]) -> str:
            token = match.group(1).upper()
            css_class = CONFIDENCE_CLASS_MAP.get(token, "confidence-unknown")
            return f'<span class="confidence-inline {css_class}">{token}</span>'

        return CONFIDENCE_PATTERN.sub(_replace_confidence, text)

    @staticmethod
    def _render_inline_markdown(value: str) -> str:
        source = str(value or "")
        if not source:
            return ""

        parts = re.split(r"(`[^`\n]*`)", source)
        output: list[str] = []
        for part in parts:
            if not part:
                continue
            if part.startswith("`") and part.endswith("`"):
                output.append(f"<code>{escape(part[1:-1])}</code>")
                continue

            escaped = str(escape(part))
            escaped = MARKDOWN_BOLD_STAR_PATTERN.sub(r"<strong>\1</strong>", escaped)
            escaped = MARKDOWN_BOLD_UNDERSCORE_PATTERN.sub(r"<strong>\1</strong>", escaped)
            escaped = MARKDOWN_ITALIC_STAR_PATTERN.sub(r"<em>\1</em>", escaped)
            escaped = MARKDOWN_ITALIC_UNDERSCORE_PATTERN.sub(r"<em>\1</em>", escaped)
            escaped = ReportGenerator._highlight_confidence_tokens(escaped)
            output.append(escaped)
        return "".join(output)

    @staticmethod
    def _markdown_to_html(value: str) -> str:
        lines = str(value).replace("\r\n", "\n").replace("\r", "\n").split("\n")
        blocks: list[str] = []
        paragraph_lines: list[str] = []
        list_items: list[str] = []
        list_type = ""
        in_code_fence = False
        code_lines: list[str] = []

        def flush_paragraph() -> None:
            nonlocal paragraph_lines
            if not paragraph_lines:
                return
            paragraph_text = "\n".join(paragraph_lines)
            rendered = ReportGenerator._render_inline_markdown(paragraph_text).replace("\n", "<br>\n")
            blocks.append(f"<p>{rendered}</p>")
            paragraph_lines = []

        def flush_list() -> None:
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
            nonlocal code_lines
            code_text = str(escape("\n".join(code_lines)))
            blocks.append(f"<pre><code>{code_text}</code></pre>")
            code_lines = []

        for line in lines:
            stripped = line.strip()

            if in_code_fence:
                if stripped.startswith("```"):
                    in_code_fence = False
                    flush_code_fence()
                    continue
                code_lines.append(line)
                continue

            if stripped.startswith("```"):
                flush_paragraph()
                flush_list()
                in_code_fence = True
                code_lines = []
                continue

            if not stripped:
                flush_paragraph()
                flush_list()
                continue

            heading_match = MARKDOWN_HEADING_PATTERN.match(stripped)
            if heading_match:
                flush_paragraph()
                flush_list()
                level = len(heading_match.group(1))
                heading_text = ReportGenerator._render_inline_markdown(heading_match.group(2))
                blocks.append(f"<h{level}>{heading_text}</h{level}>")
                continue

            ordered_match = MARKDOWN_ORDERED_LIST_PATTERN.match(stripped)
            if ordered_match:
                flush_paragraph()
                if list_type != "ol":
                    flush_list()
                    list_type = "ol"
                    list_items = []
                list_items.append(ReportGenerator._render_inline_markdown(ordered_match.group(1)))
                continue

            unordered_match = MARKDOWN_UNORDERED_LIST_PATTERN.match(stripped)
            if unordered_match:
                flush_paragraph()
                if list_type != "ul":
                    flush_list()
                    list_type = "ul"
                    list_items = []
                list_items.append(ReportGenerator._render_inline_markdown(unordered_match.group(1)))
                continue

            flush_list()
            paragraph_lines.append(line.strip())

        if in_code_fence:
            flush_code_fence()
        flush_paragraph()
        flush_list()

        return "\n".join(blocks)
