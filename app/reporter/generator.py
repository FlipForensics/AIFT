"""HTML report generation for forensic analysis results.

Renders AI analysis findings, evidence metadata, hash verification status,
and the audit trail into a self-contained HTML file using Jinja2 templates.
The generated report includes all CSS inlined so it can be opened as a
standalone file without a web server.

Key capabilities:

* **Flexible input normalisation** -- Per-artifact findings can be
  supplied as a list, a dict keyed by artifact name, or a single finding
  mapping; the generator coerces all shapes into a uniform list.
* **Logo embedding** -- The project logo is base64-encoded and embedded as
  a ``data:`` URI so the report is fully self-contained.

Markdown rendering and confidence highlighting are delegated to
:mod:`app.reporter.markdown`.

Attributes:
    DEFAULT_CASE_NAME: Fallback case name when none is provided.
    DEFAULT_TOOL_VERSION: AIFT version from :mod:`app.version`.
    DEFAULT_AI_PROVIDER: Placeholder string when the provider is unknown.
    SAFE_CASE_ID_PATTERN: Regex for sanitising case IDs.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import LOGO_FILE_CANDIDATES
from ..version import TOOL_VERSION
from .markdown import (
    CONFIDENCE_CLASS_MAP,
    CONFIDENCE_PATTERN,
    format_block,
    format_markdown_block,
)

__all__ = ["ReportGenerator"]

DEFAULT_CASE_NAME = "Untitled Investigation"
DEFAULT_TOOL_VERSION = TOOL_VERSION
DEFAULT_AI_PROVIDER = "unknown"

SAFE_CASE_ID_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


class ReportGenerator:
    """Render investigation results into a standalone HTML report.

    Sets up a Jinja2 :class:`~jinja2.Environment` with custom filters for
    Markdown-to-HTML conversion and confidence token highlighting.  The
    :meth:`generate` method assembles all case data into a template context
    and writes the rendered HTML to the case's ``reports/`` directory.

    Attributes:
        templates_dir: Directory containing Jinja2 HTML templates.
        cases_root: Parent directory where case subdirectories live.
        environment: Configured Jinja2 rendering environment.
        template: The loaded report template object.
    """

    def __init__(
        self,
        templates_dir: str | Path | None = None,
        cases_root: str | Path | None = None,
        template_name: str = "report_template.html",
    ) -> None:
        """Initialise the report generator.

        Args:
            templates_dir: Path to the Jinja2 templates directory.  Defaults
                to ``<project_root>/templates/``.
            cases_root: Parent directory for case output.  Defaults to
                ``<project_root>/cases/``.
            template_name: Filename of the Jinja2 report template.
        """
        project_root = Path(__file__).resolve().parents[2]
        self.templates_dir = Path(templates_dir) if templates_dir is not None else project_root / "templates"
        self.cases_root = Path(cases_root) if cases_root is not None else project_root / "cases"

        self.environment = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.environment.filters["format_block"] = format_block
        self.environment.filters["format_markdown_block"] = format_markdown_block
        self.template = self.environment.get_template(template_name)

    def generate(
        self,
        analysis_results: dict[str, Any],
        image_metadata: dict[str, Any] | list[dict[str, Any]],
        evidence_hashes: dict[str, Any] | list[dict[str, Any]],
        investigation_context: str,
        audit_log_entries: list[dict[str, Any]],
    ) -> Path:
        """Generate a standalone HTML report and write it to disk.

        Assembles evidence metadata, AI analysis, hash verification, and
        the audit trail into a Jinja2 template context, renders the HTML,
        and writes the output to ``cases/<case_id>/reports/``.

        Supports both the V1 single-image format and the multi-image
        format produced by :func:`run_multi_image_analysis`.  When
        ``analysis_results`` contains an ``"images"`` key, it is treated
        as multi-image; otherwise, it is automatically wrapped into a
        single-image structure for backward compatibility.

        Args:
            analysis_results: Dictionary containing per-artifact findings,
                executive summary, model info, and case identifiers.  For
                multi-image cases, the structure is::

                    {
                        "images": {
                            "<image_id>": {
                                "label": str,
                                "per_artifact": [...],
                                "summary": str,
                            },
                            ...
                        },
                        "cross_image_summary": str | None,
                        "model_info": dict,
                    }

            image_metadata: System metadata from the disk image (hostname,
                OS version, domain, IPs, etc.), or a list of such dicts
                for multi-image cases.
            evidence_hashes: Hash digests and verification status from
                evidence intake, or a list of such dicts for multi-image
                cases.
            investigation_context: Free-text description of the
                investigation scope and timeline.
            audit_log_entries: List of audit trail JSONL records.

        Returns:
            :class:`~pathlib.Path` to the generated HTML report file.

        Raises:
            ValueError: If a case identifier cannot be determined.
        """
        analysis = dict(analysis_results or {})
        audit_entries = self._normalize_audit_entries(audit_log_entries)

        # Detect multi-image vs V1 format.  The caller passes an "images"
        # dict when the case involves more than one disk image.
        has_images_key = "images" in analysis and isinstance(analysis["images"], Mapping)

        if has_images_key:
            multi_analysis = analysis
        else:
            multi_analysis = self._convert_v1_to_multi_image(analysis)

        # Normalize metadata and hashes to lists
        metadata_list = self._normalize_to_list(image_metadata)
        hashes_list = self._normalize_to_list(evidence_hashes)

        # The first metadata/hashes entry is used to resolve case-level
        # identifiers (case_id) which are shared across all images.
        first_metadata = dict(metadata_list[0]) if metadata_list else {}
        first_hashes = dict(hashes_list[0]) if hashes_list else {}

        case_id = self._resolve_case_id(analysis, first_metadata, first_hashes)
        case_name = self._resolve_case_name(analysis)
        generated_at = datetime.now(timezone.utc)
        generated_iso = generated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
        report_timestamp = generated_at.strftime("%Y%m%d_%H%M%S")

        # Build per-image data for the template
        images_data = multi_analysis.get("images", {})
        image_count = len(images_data)

        # Determine whether the template should render multi-image sections.
        # This must be True whenever multiple images are present -- either from
        # the analysis "images" dict, or from multiple metadata/hashes entries
        # (which indicates the caller supplied per-image lists even if the
        # analysis structure was not fully populated).
        is_multi = (
            image_count > 1
            or len(metadata_list) > 1
            or len(hashes_list) > 1
        )

        # Build evidence rows (one per image)
        evidence_rows = self._build_evidence_rows(metadata_list, hashes_list, images_data)

        # Build hash verification rows (one per image)
        hash_rows = self._build_hash_verification_rows(hashes_list, images_data)

        # Build per-image sections for the template
        image_sections = self._build_image_sections(images_data)

        # Cross-image summary (only for multi-image)
        cross_image_summary = self._stringify(
            multi_analysis.get("cross_image_summary"), default=""
        )

        # V1 backward-compatibility: the template has two rendering paths
        # controlled by ``is_multi_image``.  The V1 (single-image) path uses
        # ``evidence``, ``hash_verification``, ``executive_summary``, and
        # ``per_artifact_findings`` variables.  These are populated from the
        # first (and only) image's metadata/hashes so that older single-image
        # templates continue to work.  When ``is_multi`` is True the template
        # ignores these variables entirely, using ``evidence_rows``,
        # ``hash_rows``, and ``image_sections`` instead.
        #
        # We still populate ``evidence`` and ``hash_verification`` in the
        # multi-image branch as a safety net -- if the template ever falls
        # through, it will at least show first-image data rather than crash.
        evidence_summary = self._build_evidence_summary(first_metadata, first_hashes)
        hash_verification = self._resolve_hash_verification(first_hashes)

        if not is_multi:
            first_image_data = next(iter(images_data.values()), {})
            summary_text = self._stringify(
                analysis.get("summary") or analysis.get("executive_summary")
                or first_image_data.get("summary")
            )
            executive_summary = self._stringify(
                analysis.get("executive_summary") or summary_text
            )
            per_artifact = self._normalize_per_artifact_findings(
                {"per_artifact": first_image_data.get("per_artifact", [])}
            )
        else:
            executive_summary = ""
            per_artifact = []

        render_context = {
            "case_name": case_name,
            "case_id": case_id,
            "generated_at": generated_iso,
            "tool_version": self._resolve_tool_version(analysis, audit_entries),
            "ai_provider": self._resolve_ai_provider(multi_analysis),
            "logo_data_uri": self._resolve_logo_data_uri(),
            # V1 single-image variables (backward compat)
            "evidence": evidence_summary,
            "hash_verification": hash_verification,
            "investigation_context": self._stringify(investigation_context, default="No investigation context provided."),
            "executive_summary": executive_summary,
            "per_artifact_findings": per_artifact,
            "audit_entries": audit_entries,
            # Multi-image variables
            "is_multi_image": is_multi,
            "evidence_rows": evidence_rows,
            "hash_rows": hash_rows,
            "image_sections": image_sections,
            "cross_image_summary": cross_image_summary,
        }

        rendered = self.template.render(**render_context)

        report_dir = self.cases_root / case_id / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"report_{report_timestamp}.html"
        report_path.write_text(rendered, encoding="utf-8")
        return report_path

    def _convert_v1_to_multi_image(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Convert a V1 single-image analysis result to multi-image format.

        Wraps the V1 per-artifact findings and summary into a single-image
        entry under the ``"images"`` key.

        Args:
            analysis: V1-format analysis results dict.

        Returns:
            A dict in multi-image format with a single image entry.
        """
        per_artifact = analysis.get("per_artifact") or analysis.get("per_artifact_findings") or []
        summary = self._stringify(
            analysis.get("summary") or analysis.get("executive_summary")
        )
        case_name = self._resolve_case_name(analysis)

        return {
            **analysis,
            "images": {
                "default": {
                    "label": case_name,
                    "per_artifact": per_artifact,
                    "summary": summary,
                }
            },
            "cross_image_summary": None,
            "model_info": analysis.get("model_info", {}),
        }

    @staticmethod
    def _normalize_to_list(value: Any) -> list[dict[str, Any]]:
        """Normalize a single dict or list of dicts to a list of dicts.

        Args:
            value: A dict or list of dicts.

        Returns:
            A list of dicts.  Returns ``[{}]`` if *value* is ``None``.
        """
        if value is None:
            return [{}]
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [dict(item) if isinstance(item, Mapping) else {} for item in value]
        if isinstance(value, Mapping):
            return [dict(value)]
        return [{}]

    def _build_evidence_rows(
        self,
        metadata_list: list[dict[str, Any]],
        hashes_list: list[dict[str, Any]],
        images_data: Mapping[str, Any],
    ) -> list[dict[str, str]]:
        """Build a list of evidence summary rows for the multi-image template.

        Each row represents one image with its label, hostname, OS, SHA-256,
        and MD5.

        Args:
            metadata_list: List of per-image metadata dicts.
            hashes_list: List of per-image hash dicts.
            images_data: The ``images`` dict from analysis results.

        Returns:
            List of dicts with ``label``, ``hostname``, ``os_version``,
            ``sha256``, ``md5``, and ``filename`` keys.
        """
        image_entries = list(images_data.values())
        row_count = max(len(metadata_list), len(hashes_list), len(image_entries))
        rows: list[dict[str, str]] = []

        for i in range(row_count):
            meta = metadata_list[i] if i < len(metadata_list) else {}
            hashes = hashes_list[i] if i < len(hashes_list) else {}
            img = image_entries[i] if i < len(image_entries) else {}

            label = self._stringify(
                img.get("label") or meta.get("label") or meta.get("hostname"),
                default=f"Image {i + 1}",
            )
            hostname = self._stringify(meta.get("hostname"), default="Unknown")
            os_version = self._stringify(
                meta.get("os_version") or meta.get("os") or meta.get("os_type"),
                default="Unknown",
            )
            sha256 = self._stringify(hashes.get("sha256"), default="N/A")
            md5 = self._stringify(hashes.get("md5"), default="N/A")
            filename = self._stringify(
                hashes.get("filename") or hashes.get("file_name") or meta.get("filename"),
                default="Unknown",
            )

            rows.append({
                "label": label,
                "hostname": hostname,
                "os_version": os_version,
                "sha256": sha256,
                "md5": md5,
                "filename": filename,
            })

        return rows

    def _build_hash_verification_rows(
        self,
        hashes_list: list[dict[str, Any]],
        images_data: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """Build hash verification results for each image.

        Args:
            hashes_list: List of per-image hash dicts.
            images_data: The ``images`` dict from analysis results.

        Returns:
            List of dicts with ``label``, ``passed``, ``label_text``,
            ``detail``, and optional ``skipped`` keys.
        """
        image_entries = list(images_data.values())
        row_count = max(len(hashes_list), len(image_entries))
        rows: list[dict[str, Any]] = []

        for i in range(row_count):
            hashes = hashes_list[i] if i < len(hashes_list) else {}
            img = image_entries[i] if i < len(image_entries) else {}

            label = self._stringify(
                img.get("label"), default=f"Image {i + 1}"
            )
            verification = self._resolve_hash_verification(hashes)
            verification["image_label"] = label
            rows.append(verification)

        return rows

    def _build_image_sections(
        self,
        images_data: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """Build per-image sections for the multi-image report template.

        Each section contains the image label, summary, and normalized
        per-artifact findings.

        Args:
            images_data: The ``images`` dict from analysis results.

        Returns:
            List of dicts with ``image_id``, ``label``, ``summary``,
            and ``per_artifact_findings`` keys.
        """
        sections: list[dict[str, Any]] = []
        for image_id, img_data in images_data.items():
            if not isinstance(img_data, Mapping):
                continue

            label = self._stringify(img_data.get("label"), default=image_id)
            summary = self._stringify(img_data.get("summary"), default="")
            per_artifact = self._normalize_per_artifact_findings(
                {"per_artifact": img_data.get("per_artifact", [])}
            )

            sections.append({
                "image_id": image_id,
                "label": label,
                "summary": summary,
                "per_artifact_findings": per_artifact,
            })

        return sections

    def _resolve_logo_data_uri(self) -> str:
        """Locate the project logo and return it as a base64 ``data:`` URI.

        Returns:
            A ``data:image/...;base64,...`` string, or ``""`` if no logo found.
        """
        project_root = Path(__file__).resolve().parents[2]
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
        """Read a file and encode it as a base64 data URI string.

        Args:
            path: Path to the image file.

        Returns:
            A ``data:<mime>;base64,...`` URI string.
        """
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
        """Extract and sanitise a case ID from the available data sources.

        Raises:
            ValueError: If no case identifier can be determined.
        """
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
        """Determine a human-readable case name, falling back to a default."""
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
        """Determine the tool version from analysis data or audit entries."""
        explicit_version = self._stringify(analysis.get("tool_version"), default="")
        if explicit_version:
            return explicit_version

        for entry in reversed(audit_entries):
            version = self._stringify(entry.get("tool_version"), default="")
            if version:
                return version

        return DEFAULT_TOOL_VERSION

    def _resolve_ai_provider(self, analysis: Mapping[str, Any]) -> str:
        """Determine the AI provider label for the report header."""
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
        """Assemble evidence summary fields for the report template.

        Returns:
            Dictionary with ``filename``, ``sha256``, ``md5``, ``file_size``,
            ``hostname``, ``os_version``, ``domain``, and ``ips``.
        """
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
        """Determine hash verification PASS/FAIL status for the report.

        Returns:
            Dictionary with ``passed`` (bool), ``label`` (``"PASS"`` or
            ``"FAIL"``), and ``detail`` (human-readable explanation).
        """
        explicit = hashes.get("hash_verified")
        if explicit is None:
            explicit = hashes.get("verification_passed")
        if explicit is None:
            explicit = hashes.get("verified")

        if isinstance(explicit, str) and explicit.strip().lower() == "skipped":
            return {
                "passed": True,
                "skipped": True,
                "label": "SKIPPED",
                "detail": "Hash computation was skipped at user request during evidence intake.",
            }
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
        """Normalise per-artifact findings into a uniform list of dicts.

        Accepts lists, dicts keyed by artifact name, or single-finding
        mappings and coerces them into a list with consistent keys.

        Returns:
            List of dicts with ``artifact_name``, ``artifact_key``,
            ``analysis``, ``record_count``, ``time_range_start``,
            ``time_range_end``, ``key_data_points``, ``confidence_label``,
            and ``confidence_class``.
        """
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
        """Coerce various per-artifact finding shapes into a sequence."""
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
        """Return *True* if *value* appears to be a single finding mapping."""
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
        """Normalise key data points into a list of ``{timestamp, value}`` dicts."""
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
        """Normalise raw audit log entries into template-ready dicts."""
        if entries is None:
            return []

        normalized: list[dict[str, str]] = []
        for entry in entries:
            mapping = self._coerce_mapping(entry)
            if mapping is None:
                continue

            details_value = mapping.get("details")
            if isinstance(details_value, Mapping):
                details_text = json.dumps(details_value, sort_keys=True, indent=2)
                details_is_structured = True
            elif isinstance(details_value, Sequence) and not isinstance(details_value, (str, bytes, bytearray)):
                details_text = json.dumps(list(details_value), indent=2)
                details_is_structured = True
            else:
                details_text = self._stringify(details_value, default="")
                details_is_structured = False

            normalized.append(
                {
                    "timestamp": self._stringify(mapping.get("timestamp"), default="N/A"),
                    "action": self._stringify(mapping.get("action"), default="unknown"),
                    "details": details_text,
                    "details_is_structured": details_is_structured,
                    "tool_version": self._stringify(mapping.get("tool_version"), default=""),
                }
            )

        return normalized

    @staticmethod
    def _resolve_confidence(explicit_value: str, analysis_text: str) -> tuple[str, str]:
        """Determine confidence label and CSS class from explicit value or text.

        Returns:
            Tuple of ``(label, css_class)`` -- e.g. ``("HIGH", "confidence-high")``.
        """
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
        """Traverse a nested mapping using a two-element key path."""
        current: Any = mapping
        for key in path:
            if not isinstance(current, Mapping):
                return None
            current = current.get(key)
        return current

    @staticmethod
    def _coerce_mapping(value: Any) -> dict[str, Any] | None:
        """Attempt to coerce *value* into a plain dict, or return *None*."""
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
        """Format a byte count as a human-readable size string (e.g. ``1.50 GB``)."""
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
        """Format IP addresses as a comma-separated string."""
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            cleaned = [str(item).strip() for item in value if str(item).strip()]
            return ", ".join(cleaned) if cleaned else "Unknown"

        text = str(value).strip() if value is not None else ""
        return text or "Unknown"

    @staticmethod
    def _mapping_to_kv_text(value: Mapping[str, Any]) -> str:
        """Convert a mapping to a ``key=value; ...`` text representation."""
        parts = [
            f"{str(key)}={str(item)}"
            for key, item in value.items()
            if item not in (None, "")
        ]
        return "; ".join(parts)

    @staticmethod
    def _stringify(value: Any, default: str = "") -> str:
        """Convert *value* to a stripped string, returning *default* if empty."""
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default
