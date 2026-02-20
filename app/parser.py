"""Dissect integration layer for artifact parsing."""

from __future__ import annotations

import csv
from datetime import date, datetime, time
from pathlib import Path
import re
import traceback
from types import TracebackType
from time import perf_counter
from typing import Any, Callable

from dissect.target import Target
from dissect.target.exceptions import PluginError, UnsupportedPluginError


_ARTIFACT_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts" / "artifact_instructions"


def _artifact_prompt_name_candidates(artifact_key: str) -> list[str]:
    base = str(artifact_key).strip().lower()
    if not base:
        return []

    candidates: list[str] = []
    for value in (base, base.replace(".", "_"), base.replace("_", ".")):
        stem = value.strip()
        if not stem or stem in candidates:
            continue
        candidates.append(stem)
    return candidates


def _load_artifact_guidance_prompt(artifact_key: str) -> str:
    for prompt_stem in _artifact_prompt_name_candidates(artifact_key):
        prompt_path = _ARTIFACT_PROMPTS_DIR / f"{prompt_stem}.md"
        try:
            if prompt_path.is_file():
                prompt_text = prompt_path.read_text(encoding="utf-8").strip()
                if prompt_text:
                    return prompt_text
        except OSError:
            continue
    return ""


def _apply_artifact_guidance_from_prompts(registry: dict[str, dict[str, str]]) -> None:
    for artifact_key, artifact_details in registry.items():
        prompt_guidance = _load_artifact_guidance_prompt(artifact_key)
        if prompt_guidance:
            artifact_details["artifact_guidance"] = prompt_guidance
            continue

        fallback_guidance = str(
            artifact_details.get("analysis_instructions")
            or artifact_details.get("analysis_hint")
            or ""
        ).strip()
        if fallback_guidance:
            artifact_details.setdefault("artifact_guidance", fallback_guidance)
            artifact_details.setdefault("analysis_instructions", fallback_guidance)


ARTIFACT_REGISTRY = {
    "runkeys": {
        "name": "Run/RunOnce Keys",
        "category": "Persistence",
        "function": "runkeys",
        "description": (
            "Registry autorun entries that launch programs at user logon or system boot. "
            "These keys commonly store malware persistence command lines and loader stubs."
        ),
        "analysis_hint": (
            "Prioritize entries launching from user-writable paths like AppData, Temp, or Public. "
            "Flag encoded PowerShell, LOLBins, and commands added near the suspected compromise window."
        ),
    },
    "tasks": {
        "name": "Scheduled Tasks",
        "category": "Persistence",
        "function": "tasks",
        "description": (
            "Windows Task Scheduler definitions including triggers, actions, principals, and timing. "
            "Adversaries frequently use tasks for periodic execution and delayed payload launch."
        ),
        "analysis_hint": (
            "Look for newly created or modified tasks with hidden settings, unusual run accounts, or actions "
            "pointing to scripts/binaries outside Program Files and Windows directories."
        ),
    },
    "services": {
        "name": "Services",
        "category": "Persistence",
        "function": "services",
        "description": (
            "Windows service configuration and startup metadata, including image paths and service accounts. "
            "Malicious services can provide boot persistence and privilege escalation."
        ),
        "analysis_hint": (
            "Investigate auto-start services with suspicious image paths, weakly named binaries, or unexpected "
            "accounts. Correlate install/start times with process creation and event log artifacts."
        ),
    },
    "cim": {
        "name": "WMI Persistence",
        "category": "Persistence",
        "function": "cim",
        "description": (
            "WMI repository data such as event filters, consumers, and bindings used for event-driven execution. "
            "This is a common stealth persistence mechanism in fileless intrusions."
        ),
        "analysis_hint": (
            "Focus on suspicious __EventFilter, CommandLineEventConsumer, and ActiveScriptEventConsumer objects. "
            "Flag PowerShell, cmd, or script host commands triggered by system/user logon events."
        ),
    },
    "shimcache": {
        "name": "Shimcache",
        "category": "Execution",
        "function": "shimcache",
        "description": (
            "Application Compatibility Cache entries containing executable paths and file metadata observed by the OS. "
            "Entries provide execution context but do not independently prove a successful run."
        ),
        "analysis_hint": (
            "Use Shimcache to surface suspicious paths, then confirm execution with Prefetch, Amcache, or event logs. "
            "Pay attention to unsigned tools, archive extraction paths, and deleted binaries."
        ),
    },
    "amcache": {
        "name": "Amcache",
        "category": "Execution",
        "function": "amcache",
        "description": (
            "Application and file inventory from Amcache.hve, often including path, hash, compile info, and first-seen data. "
            "Useful for identifying executed or installed binaries and their provenance."
        ),
        "analysis_hint": (
            "Prioritize recently introduced executables with unknown publishers or rare install locations. "
            "Compare hashes and file names against threat intelligence and other execution artifacts."
        ),
    },
    "prefetch": {
        "name": "Prefetch",
        "category": "Execution",
        "function": "prefetch",
        "description": (
            "Windows Prefetch artifacts recording executable run metadata such as run counts, last run times, and referenced files. "
            "They are high-value evidence for userland execution on supported systems."
        ),
        "analysis_hint": (
            "Hunt for recently first-run utilities, script hosts, and remote administration tools. "
            "Review loaded file references for dropped DLLs and staging directories."
        ),
    },
    "bam": {
        "name": "BAM/DAM",
        "category": "Execution",
        "function": "bam",
        "description": (
            "Background Activity Moderator and Desktop Activity Moderator execution tracking tied to user SIDs. "
            "These entries help attribute process activity to specific user contexts."
        ),
        "analysis_hint": (
            "Correlate BAM/DAM timestamps with logons and process events to identify who launched suspicious binaries. "
            "Highlight administrative tools and scripts executed outside normal business patterns."
        ),
    },
    "userassist": {
        "name": "UserAssist",
        "category": "Execution",
        "function": "userassist",
        "description": (
            "Per-user Explorer-driven program execution traces stored in ROT13-encoded registry values. "
            "Includes run counts and last execution times for GUI-launched applications."
        ),
        "analysis_hint": (
            "Decode and review rarely used programs, renamed binaries, and LOLBins launched through Explorer. "
            "Use run-count deltas and last-run times to identify unusual user behavior."
        ),
    },
    "evtx": {
        "name": "Windows Event Logs",
        "category": "Event Logs",
        "function": "evtx",
        "description": (
            "Windows event channel records covering authentication, process creation, services, policy changes, and system health. "
            "EVTX is often the backbone for timeline and intrusion reconstruction."
        ),
        "analysis_hint": (
            "Pivot on high-signal event IDs for logon, process creation, service installs, account changes, and log clearing. "
            "Correlate actor account, host, and parent-child process chains across Security/System channels."
        ),
    },
    "defender.evtx": {
        "name": "Defender Logs",
        "category": "Event Logs",
        "function": "defender.evtx",
        "description": (
            "Microsoft Defender event logs describing detections, remediation actions, exclusions, and protection state changes. "
            "These records show what malware was seen and how protection responded."
        ),
        "analysis_hint": (
            "Identify detection names, severity, and action outcomes (blocked, quarantined, allowed, failed). "
            "Flag tamper protection events, exclusion changes, and repeated detections of the same path."
        ),
    },
    "mft": {
        "name": "MFT",
        "category": "File System",
        "function": "mft",
        "description": (
            "Master File Table metadata for NTFS files and directories, including timestamps, attributes, and record references. "
            "MFT helps reconstruct file lifecycle and artifact provenance at scale."
        ),
        "analysis_hint": (
            "Focus on executable/script creation in user profile, temp, and startup paths near incident time. "
            "Check for timestamp anomalies and suspicious rename/move patterns suggesting anti-forensics."
        ),
    },
    "usnjrnl": {
        "name": "USN Journal",
        "category": "File System",
        "function": "usnjrnl",
        "description": (
            "NTFS change journal entries capturing create, modify, rename, and delete operations over time. "
            "USN is valuable for short-lived files that no longer exist on disk."
        ),
        "analysis_hint": (
            "Track rapid create-delete or rename chains involving scripts, archives, and binaries. "
            "Correlate change reasons and timestamps with execution and network artifacts for full activity flow."
        ),
    },
    "recyclebin": {
        "name": "Recycle Bin",
        "category": "File System",
        "function": "recyclebin",
        "description": (
            "Deleted-item metadata including original paths, deletion times, and owning user context. "
            "Useful for identifying post-activity cleanup and attempted evidence removal."
        ),
        "analysis_hint": (
            "Prioritize deleted tools, scripts, archives, and credential files tied to suspicious users. "
            "Compare deletion timestamps against detection events and command history."
        ),
    },
    "browser.history": {
        "name": "Browser History",
        "category": "User Activity",
        "function": "browser.history",
        "description": (
            "Visited URL records with titles and timestamps from supported web browsers. "
            "These entries reveal user browsing intent, reconnaissance, and web-based attack paths."
        ),
        "analysis_hint": (
            "Look for phishing domains, file-sharing links, admin portals, and malware delivery infrastructure. "
            "Align visit times with downloads, process execution, and authentication events."
        ),
    },
    "browser.downloads": {
        "name": "Browser Downloads",
        "category": "User Activity",
        "function": "browser.downloads",
        "description": (
            "Browser download records linking source URLs to local file paths and timing. "
            "This artifact is key for tracing initial payload ingress and user-acquired tools."
        ),
        "analysis_hint": (
            "Flag executable, script, archive, and disk-image downloads from untrusted domains. "
            "Correlate downloaded file names and times with Prefetch, Amcache, and Defender activity."
        ),
    },
    "powershell_history": {
        "name": "PowerShell History",
        "category": "User Activity",
        "function": "powershell_history",
        "description": (
            "PSReadLine command history capturing interactive PowerShell commands entered by users. "
            "Often exposes attacker tradecraft such as reconnaissance, staging, and command-and-control setup."
        ),
        "analysis_hint": (
            "Hunt for encoded commands, download cradles, credential access, and remote execution cmdlets. "
            "Note gaps or abrupt truncation that may indicate history clearing or alternate execution methods."
        ),
    },
    "activitiescache": {
        "name": "Activities Cache",
        "category": "User Activity",
        "function": "activitiescache",
        "description": (
            "Windows Timeline activity records reflecting user interactions with apps, documents, and URLs. "
            "Provides broader behavioral context across applications and time."
        ),
        "analysis_hint": (
            "Use it to build user intent timelines around suspicious periods and identify staging behavior. "
            "Prioritize activity involving remote access tools, cloud storage, and sensitive document paths."
        ),
    },
    "sru.network_data": {
        "name": "SRUM Network Data",
        "category": "Network",
        "function": "sru.network_data",
        "description": (
            "System Resource Usage Monitor network telemetry with per-application usage over time. "
            "Shows which apps consumed network bandwidth and when."
        ),
        "analysis_hint": (
            "Identify unusual outbound-heavy applications, especially unsigned or rarely seen executables. "
            "Correlate spikes with execution artifacts and possible data exfiltration windows."
        ),
    },
    "sru.application": {
        "name": "SRUM Application",
        "category": "Network",
        "function": "sru.application",
        "description": (
            "SRUM application resource usage records that provide process-level activity context across time slices. "
            "Helpful for spotting persistence or background abuse patterns."
        ),
        "analysis_hint": (
            "Surface low-prevalence applications active during the incident period or outside baseline hours. "
            "Cross-check with BAM, Prefetch, and network logs to confirm suspicious sustained activity."
        ),
    },
    "shellbags": {
        "name": "Shellbags",
        "category": "Registry",
        "function": "shellbags",
        "description": (
            "Registry traces of folders viewed in Explorer, including local, removable, and network paths. "
            "Shellbags can preserve evidence even after files or folders are deleted."
        ),
        "analysis_hint": (
            "Look for access to hidden folders, USB volumes, network shares, and unusual archive locations. "
            "Use viewed-path chronology to support staging and collection hypotheses."
        ),
    },
    "usb": {
        "name": "USB History",
        "category": "Registry",
        "function": "usb",
        "description": (
            "Registry evidence of connected USB devices, including identifiers and connection history metadata. "
            "Useful for tracking removable media usage and potential data transfer vectors."
        ),
        "analysis_hint": (
            "Identify unknown devices and compare first/last seen times with suspicious file and user activity. "
            "Focus on storage-class devices connected near possible exfiltration or staging events."
        ),
    },
    "muicache": {
        "name": "MUIcache",
        "category": "Registry",
        "function": "muicache",
        "description": (
            "Cache of executable display strings written when programs are launched via the shell. "
            "Can provide residual execution clues for binaries no longer present."
        ),
        "analysis_hint": (
            "Hunt for suspicious executable paths and uncommon tool names absent from standard software inventories. "
            "Correlate entries with UserAssist and Shimcache for stronger execution confidence."
        ),
    },
    "sam": {
        "name": "SAM Users",
        "category": "Security",
        "function": "sam",
        "description": (
            "Local Security Account Manager user account records and account state metadata. "
            "This artifact supports detection of unauthorized local account creation and privilege abuse."
        ),
        "analysis_hint": (
            "Flag newly created, enabled, or reactivated local accounts, especially admin-capable users. "
            "Correlate account changes with logon events and lateral movement artifacts."
        ),
    },
    "defender.quarantine": {
        "name": "Defender Quarantine",
        "category": "Security",
        "function": "defender.quarantine",
        "description": (
            "Metadata about items quarantined by Microsoft Defender, including source path and detection context. "
            "Indicates which suspicious files were contained and where they originated."
        ),
        "analysis_hint": (
            "Confirm whether detections were successfully quarantined and whether the same paths reappear later. "
            "Use quarantine artifacts to pivot into file system, execution, and persistence traces."
        ),
    },
}

_apply_artifact_guidance_from_prompts(ARTIFACT_REGISTRY)

UNKNOWN_VALUE = "Unknown"
EVTX_MAX_RECORDS_PER_FILE = 500_000
MAX_RECORDS_PER_ARTIFACT = 1_000_000


class ForensicParser:
    """Parse supported forensic artifacts from a Dissect target into CSV files."""

    def __init__(
        self,
        evidence_path: str | Path,
        case_dir: str | Path,
        audit_logger: Any,
        parsed_dir: str | Path | None = None,
    ) -> None:
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
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        del exc_type, exc_val, exc_tb
        self.close()
        return False

    def get_image_metadata(self) -> dict[str, str]:
        """Return key metadata fields from the Dissect Target object."""
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
        """Return the artifact registry annotated with availability for this target."""
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
        for namespace in function_name.split("."):
            current = getattr(current, namespace)

        return current() if callable(current) else current

    def parse_artifact(
        self,
        artifact_key: str,
        progress_callback: Callable[..., None] | None = None,
    ) -> dict[str, Any]:
        """Parse one artifact and write its records to CSV."""
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
        """Read a target attribute by trying multiple names and handling missing values."""
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
        records: Any,
        csv_output_path: Path,
        progress_callback: Callable[..., None] | None,
        artifact_key: str,
    ) -> int:
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
        if value is None:
            return ""
        if isinstance(value, (datetime, date, time)):
            return value.isoformat()
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value).hex()
        return str(value)

    @staticmethod
    def _find_record_value(record_dict: dict[str, Any], candidate_keys: tuple[str, ...]) -> str:
        for key in candidate_keys:
            if key in record_dict and record_dict[key] not in (None, ""):
                return str(record_dict[key])
        return ""

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
        return cleaned or "artifact"

    @staticmethod
    def _is_evtx_artifact(function_name: str) -> bool:
        return function_name == "evtx" or function_name.endswith(".evtx")

    @staticmethod
    def _emit_progress(
        progress_callback: Callable[..., None],
        artifact_key: str,
        record_count: int,
    ) -> None:
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
