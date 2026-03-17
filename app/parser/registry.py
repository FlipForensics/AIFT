"""Artifact registry and prompt-loading helpers for forensic parsing.

Maintains the :data:`ARTIFACT_REGISTRY` catalogue that maps each supported
forensic artifact to its Dissect function name, category, human-readable
description, and analysis guidance.  Guidance text is loaded from Markdown
files in ``prompts/artifact_instructions/`` when available, falling back to
inline ``analysis_hint`` values.

Attributes:
    ARTIFACT_REGISTRY: Mapping of artifact key to metadata dict (name,
        category, Dissect function, description, analysis hints).
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["ARTIFACT_REGISTRY"]

_ARTIFACT_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts" / "artifact_instructions"


def _artifact_prompt_name_candidates(artifact_key: str) -> list[str]:
    """Generate candidate file stems for loading an artifact guidance prompt.

    Produces variants with dots replaced by underscores and vice-versa so
    that ``browser.history`` matches ``browser_history.md``.

    Args:
        artifact_key: Artifact identifier (e.g. ``"browser.history"``).

    Returns:
        List of lowercased candidate stems, deduplicated.
    """
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
    """Load a Markdown guidance prompt for an artifact from the prompts directory.

    Args:
        artifact_key: Artifact identifier to look up.

    Returns:
        The prompt text, or an empty string if no matching file is found.
    """
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
    """Populate ``artifact_guidance`` on each registry entry from prompt files.

    For every artifact, attempts to load a matching Markdown prompt from
    ``prompts/artifact_instructions/``.  Falls back to the inline
    ``analysis_instructions`` or ``analysis_hint`` when no file exists.

    Args:
        registry: The mutable :data:`ARTIFACT_REGISTRY` dictionary.
    """
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
