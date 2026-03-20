"""Dissect integration layer for forensic artifact parsing.

Wraps the Dissect framework's ``Target`` API to extract Windows forensic
artifacts from disk images (E01, VMDK, VHD, raw, etc.) and stream them
into CSV files for downstream AI analysis.

Key responsibilities:

* **Evidence opening** -- :class:`ForensicParser` opens a Dissect
  ``Target`` in read-only mode from any supported container format.
* **CSV streaming** -- Records are streamed to CSV one row at a time,
  never materialised in memory, allowing safe handling of high-volume
  artifacts such as EVTX and MFT (millions of records).
* **EVTX splitting** -- Event log records are automatically partitioned
  by channel/provider into separate CSV files, with additional part files
  created when a single channel exceeds :data:`EVTX_MAX_RECORDS_PER_FILE`.
* **Schema evolution** -- When a Dissect plugin yields records with
  varying schemas, CSV headers are expanded dynamically and the file is
  rewritten once to ensure a consistent header row.

Attributes:
    UNKNOWN_VALUE: Sentinel string used when a target attribute cannot be read.
    EVTX_MAX_RECORDS_PER_FILE: Maximum rows per EVTX CSV part file.
    MAX_RECORDS_PER_ARTIFACT: Hard cap on rows written for any single artifact.
"""

from __future__ import annotations

import csv
from datetime import date, datetime, time
from pathlib import Path
import re
import traceback
from types import TracebackType
from time import perf_counter
import logging
from typing import Any, Callable, Iterable

from dissect.target import Target
from dissect.target.exceptions import PluginError, UnsupportedPluginError

from .registry import ARTIFACT_REGISTRY

__all__ = ["ForensicParser"]

logger = logging.getLogger(__name__)

UNKNOWN_VALUE = "Unknown"
EVTX_MAX_RECORDS_PER_FILE = 500_000
MAX_RECORDS_PER_ARTIFACT = 1_000_000


class ForensicParser:
    """Parse supported forensic artifacts from a Dissect target into CSV files.

    Opens a disk image via Dissect's ``Target.open()``, queries available
    artifacts, and streams their records to CSV files in the case's parsed
    directory.  Implements the context manager protocol for deterministic
    resource cleanup.

    Attributes:
        evidence_path: Path to the source evidence file.
        case_dir: Root directory for this forensic case.
        audit_logger: :class:`~app.audit.AuditLogger` for recording actions.
        parsed_dir: Directory where output CSV files are written.
        target: The open Dissect ``Target`` handle.
    """

    def __init__(
        self,
        evidence_path: str | Path,
        case_dir: str | Path,
        audit_logger: Any,
        parsed_dir: str | Path | None = None,
    ) -> None:
        """Initialise the parser and open the Dissect target.

        Args:
            evidence_path: Path to the disk image or evidence container.
            case_dir: Case-specific directory for output and audit data.
            audit_logger: Logger instance for writing audit trail entries.
            parsed_dir: Optional override for the CSV output directory.
                Defaults to ``<case_dir>/parsed/``.
        """
        self.evidence_path = Path(evidence_path)
        self.case_dir = Path(case_dir)
        self.audit_logger = audit_logger
        self.parsed_dir = Path(parsed_dir) if parsed_dir is not None else self.case_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)
        self.target = Target.open(self.evidence_path)
        self._closed = False

    def close(self) -> None:
        """Close the underlying Dissect target handle."""
        if self._closed:
            return

        try:
            close_method = getattr(self.target, "close", None)
        except Exception:
            close_method = None
        if callable(close_method):
            close_method()
        self._closed = True

    def __enter__(self) -> ForensicParser:
        """Enter the runtime context and return the parser instance."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """Exit the runtime context, closing the Dissect target."""
        del exc_type, exc_val, exc_tb
        self.close()
        return False

    def get_image_metadata(self) -> dict[str, str]:
        """Extract key system metadata from the Dissect target.

        Attempts multiple attribute name variants for each field (e.g.
        ``hostname``, ``computer_name``, ``name``) to accommodate
        different OS profiles.

        Returns:
            Dictionary with keys ``hostname``, ``os_version``, ``domain``,
            ``ips``, ``timezone``, and ``install_date``.
        """
        hostname = str(self._safe_read_target_attribute(("hostname", "computer_name", "name")))
        os_version = str(self._safe_read_target_attribute(("os_version", "version")))
        domain = str(self._safe_read_target_attribute(("domain", "dns_domain", "workgroup")))
        timezone = str(self._safe_read_target_attribute(("timezone", "tz")))
        install_date = str(self._safe_read_target_attribute(("install_date", "installdate")))

        ips_value = self._safe_read_target_attribute(("ips", "ip_addresses", "ip"))
        if isinstance(ips_value, (list, tuple, set)):
            ips = ", ".join(str(value) for value in ips_value if value not in (None, ""))
            if not ips:
                ips = UNKNOWN_VALUE
        else:
            ips = str(ips_value)

        return {
            "hostname": hostname,
            "os_version": os_version,
            "domain": domain,
            "ips": ips,
            "timezone": timezone,
            "install_date": install_date,
        }

    def get_available_artifacts(self) -> list[dict[str, Any]]:
        """Return the artifact registry annotated with availability flags.

        Probes the Dissect target for each registered artifact and sets
        an ``available`` boolean on the returned metadata dictionaries.

        Returns:
            List of artifact metadata dicts, each augmented with ``key``
            and ``available`` fields.
        """
        available_artifacts: list[dict[str, Any]] = []
        for artifact_key, artifact_details in ARTIFACT_REGISTRY.items():
            function_name = str(artifact_details.get("function", artifact_key))
            try:
                available = bool(self.target.has_function(function_name))
            except (PluginError, UnsupportedPluginError):
                available = False

            available_artifact = dict(artifact_details)
            available_artifact["key"] = artifact_key
            available_artifact["available"] = available
            available_artifacts.append(available_artifact)

        return available_artifacts

    def _call_target_function(self, function_name: str) -> Any:
        """Invoke a Dissect function on the target, including namespaced functions.

        For simple names like ``"shimcache"`` it calls ``target.shimcache()``.
        For dotted names like ``"browser.history"`` it traverses the namespace
        chain (``target.browser.history()``) and calls the final attribute.
        """
        if "." not in function_name:
            function = getattr(self.target, function_name)
            return function() if callable(function) else function

        current: Any = self.target
        parts = function_name.split(".")
        try:
            for namespace in parts:
                current = getattr(current, namespace)
        except Exception:
            logger.warning(
                "Failed to resolve nested function '%s' (stopped at '%s')",
                function_name,
                namespace,
                exc_info=True,
            )
            raise

        return current() if callable(current) else current

    def parse_artifact(
        self,
        artifact_key: str,
        progress_callback: Callable[..., None] | None = None,
    ) -> dict[str, Any]:
        """Parse a single artifact and stream its records to one or more CSV files.

        Logs ``parsing_started``, ``parsing_completed`` (or ``parsing_failed``)
        to the audit trail.  EVTX artifacts are split by channel/provider
        into separate CSV files.

        Args:
            artifact_key: Key from :data:`ARTIFACT_REGISTRY` identifying
                the artifact to parse.
            progress_callback: Optional callback invoked every 1 000 records
                with progress information.

        Returns:
            Result dictionary with keys ``csv_path``, ``record_count``,
            ``duration_seconds``, ``success``, and ``error``.  EVTX
            results also include a ``csv_paths`` list.
        """
        artifact = ARTIFACT_REGISTRY.get(artifact_key)
        if artifact is None:
            return {
                "csv_path": "",
                "record_count": 0,
                "duration_seconds": 0.0,
                "success": False,
                "error": f"Unknown artifact key: {artifact_key}",
            }

        function_name = str(artifact.get("function", artifact_key))
        start_time = perf_counter()
        record_count = 0
        csv_path = ""

        self.audit_logger.log(
            "parsing_started",
            {
                "artifact_key": artifact_key,
                "artifact_name": artifact.get("name", artifact_key),
                "function": function_name,
            },
        )

        try:
            records = self._call_target_function(function_name)
            if self._is_evtx_artifact(function_name):
                all_csv_paths, record_count = self._write_evtx_records(
                    artifact_key=artifact_key,
                    records=records,
                    progress_callback=progress_callback,
                )
                if all_csv_paths:
                    csv_path = str(all_csv_paths[0])
                else:
                    empty_output = self.parsed_dir / f"{self._sanitize_filename(artifact_key)}.csv"
                    empty_output.touch(exist_ok=True)
                    csv_path = str(empty_output)
                    all_csv_paths = [empty_output]
            else:
                csv_output = self.parsed_dir / f"{self._sanitize_filename(artifact_key)}.csv"
                record_count = self._write_records_to_csv(
                    records=records,
                    csv_output_path=csv_output,
                    progress_callback=progress_callback,
                    artifact_key=artifact_key,
                )
                csv_path = str(csv_output)

            duration = perf_counter() - start_time
            self.audit_logger.log(
                "parsing_completed",
                {
                    "artifact_key": artifact_key,
                    "artifact_name": artifact.get("name", artifact_key),
                    "function": function_name,
                    "record_count": record_count,
                    "duration_seconds": round(duration, 6),
                    "csv_path": csv_path,
                },
            )

            result: dict[str, Any] = {
                "csv_path": csv_path,
                "record_count": record_count,
                "duration_seconds": duration,
                "success": True,
                "error": None,
            }
            if self._is_evtx_artifact(function_name):
                result["csv_paths"] = [str(p) for p in all_csv_paths]
            return result
        except Exception as error:
            duration = perf_counter() - start_time
            error_message = str(error)
            error_traceback = traceback.format_exc()
            self.audit_logger.log(
                "parsing_failed",
                {
                    "artifact_key": artifact_key,
                    "artifact_name": artifact.get("name", artifact_key),
                    "function": function_name,
                    "error": error_message,
                    "traceback": error_traceback,
                    "duration_seconds": round(duration, 6),
                },
            )
            return {
                "csv_path": "",
                "record_count": record_count,
                "duration_seconds": duration,
                "success": False,
                "error": error_message,
            }

    def _safe_read_target_attribute(self, attribute_names: tuple[str, ...]) -> Any:
        """Read a target attribute by trying multiple candidate names.

        Args:
            attribute_names: Ordered tuple of attribute names to try.

        Returns:
            The first non-empty value found, or :data:`UNKNOWN_VALUE`.
        """
        for attribute_name in attribute_names:
            try:
                value = getattr(self.target, attribute_name)
            except Exception:
                continue

            if callable(value):
                try:
                    value = value()
                except Exception:
                    continue

            if value in (None, ""):
                continue

            return value

        return UNKNOWN_VALUE

    def _write_records_to_csv(
        self,
        records: Iterable[Any],
        csv_output_path: Path,
        progress_callback: Callable[..., None] | None,
        artifact_key: str,
    ) -> int:
        """Stream Dissect records to a CSV file, handling dynamic schemas.

        If the record schema expands mid-stream (new columns appear), the
        file is rewritten at the end with the complete header row via
        :meth:`_rewrite_csv_with_expanded_headers`.

        Args:
            records: Iterable of Dissect record objects.
            csv_output_path: Destination CSV file path.
            progress_callback: Optional progress callback.
            artifact_key: Artifact key for audit/progress reporting.

        Returns:
            Total number of records written.
        """
        record_count = 0
        fieldnames: list[str] = []
        fieldnames_set: set[str] = set()
        headers_expanded = False

        with csv_output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer: csv.DictWriter | None = None
            for record in records:
                record_dict = self._record_to_dict(record)

                new_keys = [str(k) for k in record_dict.keys() if str(k) not in fieldnames_set]
                if new_keys:
                    fieldnames.extend(new_keys)
                    fieldnames_set.update(new_keys)
                    if writer is not None:
                        headers_expanded = True
                    writer = csv.DictWriter(
                        csv_file, fieldnames=fieldnames, restval="", extrasaction="ignore",
                    )
                    if not headers_expanded:
                        writer.writeheader()

                row = {
                    fn: self._stringify_csv_value(record_dict.get(fn))
                    for fn in fieldnames
                }
                if writer is not None:
                    writer.writerow(row)
                record_count += 1

                if record_count >= MAX_RECORDS_PER_ARTIFACT:
                    self.audit_logger.log(
                        "parsing_capped",
                        {
                            "artifact_key": artifact_key,
                            "record_count": record_count,
                            "max_records": MAX_RECORDS_PER_ARTIFACT,
                            "message": f"Artifact capped at {MAX_RECORDS_PER_ARTIFACT:,} rows",
                        },
                    )
                    break

                if progress_callback is not None and record_count % 1000 == 0:
                    self._emit_progress(progress_callback, artifact_key, record_count)

        if headers_expanded and record_count > 0:
            self._rewrite_csv_with_expanded_headers(csv_output_path, fieldnames)

        if progress_callback is not None:
            self._emit_progress(progress_callback, artifact_key, record_count)

        return record_count

    def _rewrite_csv_with_expanded_headers(self, csv_path: Path, fieldnames: list[str]) -> None:
        """Rewrite a CSV whose header is incomplete due to mid-stream schema changes.

        Because fieldnames are only ever appended, row values are positionally
        aligned: shorter rows (written before expansion) just need empty-string
        padding for the new trailing columns.
        """
        temp_path = csv_path.with_suffix(".csv.tmp")
        num_fields = len(fieldnames)
        with csv_path.open("r", newline="", encoding="utf-8") as src, \
             temp_path.open("w", newline="", encoding="utf-8") as dst:
            reader = csv.reader(src)
            csv_writer = csv.writer(dst)
            csv_writer.writerow(fieldnames)
            next(reader, None)  # skip original (incomplete) header
            for row in reader:
                if len(row) < num_fields:
                    row.extend([""] * (num_fields - len(row)))
                csv_writer.writerow(row)
        temp_path.replace(csv_path)

    def _write_evtx_records(
        self,
        artifact_key: str,
        records: Any,
        progress_callback: Callable[..., None] | None,
    ) -> tuple[list[Path], int]:
        """Stream EVTX records into per-channel CSV files with automatic splitting.

        Records are grouped by their channel or provider name.  When a
        single group exceeds :data:`EVTX_MAX_RECORDS_PER_FILE`, a new
        part file is created.

        Args:
            artifact_key: Artifact key for filename construction.
            records: Iterable of Dissect EVTX record objects.
            progress_callback: Optional progress callback.

        Returns:
            Tuple of ``(csv_paths, total_record_count)``.
        """
        writers: dict[str, dict[str, Any]] = {}
        csv_paths: list[Path] = []
        record_count = 0

        try:
            for record in records:
                record_dict = self._record_to_dict(record)
                group_name = self._extract_evtx_group_name(record_dict)

                writer_state = writers.get(group_name)
                if writer_state is None:
                    writer_state = self._open_evtx_writer(artifact_key=artifact_key, group_name=group_name, part=1)
                    writers[group_name] = writer_state
                    csv_paths.append(writer_state["path"])
                elif writer_state["records_in_file"] >= EVTX_MAX_RECORDS_PER_FILE:
                    writer_state["handle"].close()
                    next_part = int(writer_state["part"]) + 1
                    writer_state = self._open_evtx_writer(
                        artifact_key=artifact_key,
                        group_name=group_name,
                        part=next_part,
                    )
                    writers[group_name] = writer_state
                    csv_paths.append(writer_state["path"])

                if writer_state["fieldnames"] is None:
                    fieldnames = [str(key) for key in record_dict.keys()]
                    writer_state["fieldnames"] = fieldnames
                    writer_state["writer"] = csv.DictWriter(
                        writer_state["handle"],
                        fieldnames=fieldnames,
                        extrasaction="ignore",
                    )
                    writer_state["writer"].writeheader()

                fieldnames = writer_state["fieldnames"]
                row = {
                    fieldname: self._stringify_csv_value(record_dict.get(fieldname))
                    for fieldname in fieldnames
                }
                writer_state["writer"].writerow(row)
                writer_state["records_in_file"] += 1
                record_count += 1

                if progress_callback is not None and record_count % 1000 == 0:
                    self._emit_progress(progress_callback, artifact_key, record_count)
        finally:
            for writer_state in writers.values():
                writer_state["handle"].close()

        if progress_callback is not None:
            self._emit_progress(progress_callback, artifact_key, record_count)

        return csv_paths, record_count

    def _open_evtx_writer(self, artifact_key: str, group_name: str, part: int) -> dict[str, Any]:
        """Open a new CSV file for an EVTX channel group and return writer state.

        Args:
            artifact_key: Parent artifact key for filename construction.
            group_name: EVTX channel or provider name.
            part: 1-based part number for multi-file splits.

        Returns:
            Dictionary containing ``path``, ``handle``, ``writer``,
            ``fieldnames``, ``records_in_file``, and ``part``.
        """
        artifact_stub = self._sanitize_filename(artifact_key)
        group_stub = self._sanitize_filename(group_name)
        filename = f"{artifact_stub}_{group_stub}.csv" if part == 1 else f"{artifact_stub}_{group_stub}_part{part}.csv"
        output_path = self.parsed_dir / filename

        handle = output_path.open("w", newline="", encoding="utf-8")
        return {
            "path": output_path,
            "handle": handle,
            "writer": None,
            "fieldnames": None,
            "records_in_file": 0,
            "part": part,
        }

    def _extract_evtx_group_name(self, record_dict: dict[str, Any]) -> str:
        """Determine the channel/provider group name for an EVTX record.

        Checks multiple candidate keys (``channel``, ``Channel``,
        ``provider``, etc.) and returns the first non-empty value.

        Args:
            record_dict: Dictionary representation of the EVTX record.

        Returns:
            Channel or provider name, or ``"unknown"`` if none found.
        """
        channel = self._find_record_value(
            record_dict,
            (
                "channel",
                "Channel",
                "log_name",
                "LogName",
                "event_log",
                "EventLog",
            ),
        )
        provider = self._find_record_value(
            record_dict,
            (
                "provider",
                "Provider",
                "provider_name",
                "ProviderName",
                "source",
                "Source",
            ),
        )

        if channel:
            return channel
        if provider:
            return provider
        return "unknown"

    @staticmethod
    def _record_to_dict(record: Any) -> dict[str, Any]:
        """Convert a Dissect record to a plain dictionary.

        Handles Dissect ``Record`` objects (via ``_asdict()``), plain
        dicts, and objects with a ``__dict__``.

        Args:
            record: A Dissect record or dict-like object.

        Returns:
            A plain dictionary of field names to values.

        Raises:
            TypeError: If the record cannot be converted.
        """
        if hasattr(record, "_asdict"):
            as_dict = record._asdict()
            if isinstance(as_dict, dict):
                return dict(as_dict)

        if isinstance(record, dict):
            return dict(record)

        try:
            return dict(vars(record))
        except TypeError as exc:
            raise TypeError("Artifact record cannot be converted to a dictionary.") from exc

    @staticmethod
    def _stringify_csv_value(value: Any) -> str:
        """Convert a record field value to a CSV-safe string.

        Handles ``datetime``, ``bytes``, ``None``, and other types that
        Dissect records may yield.

        Args:
            value: The raw field value from a Dissect record.

        Returns:
            String representation suitable for CSV output.
        """
        if value is None:
            return ""
        if isinstance(value, (datetime, date, time)):
            return value.isoformat()
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            if len(raw) > 512:
                return raw[:512].hex() + "..."
            return raw.hex()
        return str(value)

    @staticmethod
    def _find_record_value(record_dict: dict[str, Any], candidate_keys: tuple[str, ...]) -> str:
        """Return the first non-empty value from *candidate_keys* in *record_dict*.

        Args:
            record_dict: Dictionary to search.
            candidate_keys: Ordered tuple of keys to try.

        Returns:
            The first non-empty string value, or ``""`` if none found.
        """
        for key in candidate_keys:
            if key in record_dict and record_dict[key] not in (None, ""):
                return str(record_dict[key])
        return ""

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        """Replace non-alphanumeric characters with underscores for safe filenames.

        Args:
            value: Raw string to sanitise.

        Returns:
            Filesystem-safe string, or ``"artifact"`` if empty after cleaning.
        """
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
        return cleaned or "artifact"

    @staticmethod
    def _is_evtx_artifact(function_name: str) -> bool:
        """Return *True* if *function_name* indicates an EVTX artifact."""
        return function_name == "evtx" or function_name.endswith(".evtx")

    @staticmethod
    def _emit_progress(
        progress_callback: Callable[..., None],
        artifact_key: str,
        record_count: int,
    ) -> None:
        """Invoke the progress callback, tolerating varying signatures.

        Tries ``callback(dict)``, then ``callback(key, count)``, then
        ``callback(count)`` to accommodate different caller conventions.

        Args:
            progress_callback: Callable to invoke.
            artifact_key: Current artifact being parsed.
            record_count: Number of records processed so far.
        """
        payload = {"artifact_key": artifact_key, "record_count": record_count}
        try:
            progress_callback(payload)
            return
        except TypeError:
            pass

        try:
            progress_callback(artifact_key, record_count)  # type: ignore[misc]
            return
        except TypeError:
            pass

        try:
            progress_callback(record_count)  # type: ignore[misc]
        except Exception:
            return
