"""Artifact registry and prompt-loading helpers for forensic parsing.

Maintains OS-specific artifact registries that map each supported forensic
artifact to its Dissect function name, category, human-readable description,
and analysis guidance.  Guidance text is loaded from Markdown files in
``prompts/artifact_instructions/`` (Windows) or
``prompts/artifact_instructions_linux/`` (Linux) when available, falling back to inline
``analysis_hint`` values.

Attributes:
    WINDOWS_ARTIFACT_REGISTRY: Windows artifact catalogue.
    LINUX_ARTIFACT_REGISTRY: Linux artifact catalogue.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "LINUX_ARTIFACT_REGISTRY",
    "WINDOWS_ARTIFACT_REGISTRY",
    "get_artifact_registry",
]

_ARTIFACT_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts" / "artifact_instructions"
_LINUX_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts" / "artifact_instructions_linux"


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


def _load_artifact_guidance_prompt(
    artifact_key: str,
    prompts_dir: Path | None = None,
) -> str:
    """Load a Markdown guidance prompt for an artifact from a prompts directory.

    Args:
        artifact_key: Artifact identifier to look up.
        prompts_dir: Directory to search for prompt files.  Defaults to
            :data:`_ARTIFACT_PROMPTS_DIR` (Windows prompts).

    Returns:
        The prompt text, or an empty string if no matching file is found.
    """
    search_dir = prompts_dir if prompts_dir is not None else _ARTIFACT_PROMPTS_DIR
    for prompt_stem in _artifact_prompt_name_candidates(artifact_key):
        prompt_path = search_dir / f"{prompt_stem}.md"
        try:
            if prompt_path.is_file():
                prompt_text = prompt_path.read_text(encoding="utf-8").strip()
                if prompt_text:
                    return prompt_text
        except (OSError, UnicodeDecodeError):
            continue
    return ""


def _apply_artifact_guidance_from_prompts(
    registry: dict[str, dict[str, str]],
    prompts_dir: Path | None = None,
) -> None:
    """Populate ``artifact_guidance`` on each registry entry from prompt files.

    For every artifact, attempts to load a matching Markdown prompt from
    the given prompts directory.  Falls back to the inline
    ``analysis_instructions`` or ``analysis_hint`` when no file exists.

    Args:
        registry: The mutable artifact registry dictionary.
        prompts_dir: Directory to search for prompt files.  Defaults to
            :data:`_ARTIFACT_PROMPTS_DIR` (Windows prompts).
    """
    for artifact_key, artifact_details in registry.items():
        prompt_guidance = _load_artifact_guidance_prompt(artifact_key, prompts_dir)
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


WINDOWS_ARTIFACT_REGISTRY: dict[str, dict[str, str]] = {
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

_apply_artifact_guidance_from_prompts(WINDOWS_ARTIFACT_REGISTRY)

# ---------------------------------------------------------------------------
# Linux artifact registry
# ---------------------------------------------------------------------------

LINUX_ARTIFACT_REGISTRY: dict[str, dict[str, str]] = {
    # -- Persistence --------------------------------------------------------
    "cronjobs": {
        "name": "Cron Jobs",
        "category": "Persistence",
        "function": "cronjobs",
        "description": (
            "Scheduled tasks defined in user crontabs and system-wide /etc/cron.* directories. "
            "Cron is a common persistence and periodic-execution mechanism on Linux systems."
        ),
        "analysis_hint": (
            "Flag cron entries that download or execute from /tmp, /dev/shm, or user-writable paths. "
            "Look for base64-encoded commands, reverse shells, and entries added near the incident window."
        ),
    },
    "services": {
        "name": "Systemd Services",
        "category": "Persistence",
        "function": "services",
        "description": (
            "Systemd unit files describing services, their startup configuration, and current state. "
            "Dissect's services function is OS-aware and returns Linux systemd units on Linux targets."
        ),
        "analysis_hint": (
            "Identify services with ExecStart pointing to unusual paths (/tmp, /var/tmp, user home dirs). "
            "Flag recently created or modified unit files, units set to restart on failure, and masked units."
        ),
    },
    # -- Shell History ------------------------------------------------------
    "bash_history": {
        "name": "Bash History",
        "category": "Shell History",
        "function": "bash_history",
        "description": (
            "Per-user .bash_history files recording interactive shell commands. "
            "Highest-value artifact on Linux for understanding attacker activity."
        ),
        "analysis_hint": (
            "Hunt for curl/wget downloads, base64 encoding/decoding, reverse shells (bash -i, /dev/tcp), "
            "credential access (cat /etc/shadow), reconnaissance (id, whoami, uname -a), persistence "
            "installation (crontab -e, systemctl enable), and log tampering (truncate, shred, rm /var/log). "
            "Sparse or empty history for active accounts may indicate clearing (history -c, HISTFILE=/dev/null)."
        ),
    },
    "zsh_history": {
        "name": "Zsh History",
        "category": "Shell History",
        "function": "zsh_history",
        "description": (
            "Per-user .zsh_history files recording Zsh shell commands with optional timestamps. "
            "Zsh history may include timing data not present in bash history."
        ),
        "analysis_hint": (
            "Apply the same suspicious-command patterns as bash_history. "
            "Zsh extended history format includes timestamps — use them for timeline correlation."
        ),
    },
    "fish_history": {
        "name": "Fish History",
        "category": "Shell History",
        "function": "fish_history",
        "description": (
            "Per-user Fish shell history stored in YAML-like format with timestamps. "
            "Less common but may capture activity missed by bash/zsh."
        ),
        "analysis_hint": (
            "Apply the same suspicious-command patterns as bash_history. "
            "Fish history includes timestamps per command — correlate with login records."
        ),
    },
    "python_history": {
        "name": "Python History",
        "category": "Shell History",
        "function": "python_history",
        "description": (
            "Python REPL history from interactive interpreter sessions. "
            "May reveal attacker use of Python for scripting, exploitation, or data manipulation."
        ),
        "analysis_hint": (
            "Look for import of socket/subprocess/os modules, file read/write operations on "
            "sensitive paths, and network connection attempts. Python is commonly used for "
            "exploit development and post-exploitation tooling."
        ),
    },
    # -- Authentication -----------------------------------------------------
    "wtmp": {
        "name": "Login Records (wtmp)",
        "category": "Authentication",
        "function": "wtmp",
        "description": (
            "Successful login/logout records including user, terminal, source IP, and timestamps. "
            "Linux equivalent of Windows logon events."
        ),
        "analysis_hint": (
            "Flag logins from unexpected IPs, logins at unusual hours, root logins via SSH, "
            "and logins from accounts that should not be interactive. Cross-check with auth logs "
            "and shell history. wtmp can be tampered with — missing records or time gaps may "
            "indicate editing."
        ),
    },
    "btmp": {
        "name": "Failed Logins (btmp)",
        "category": "Authentication",
        "function": "btmp",
        "description": (
            "Failed login attempt records including user, source IP, and timestamps. "
            "High volumes indicate brute-force attacks or credential stuffing."
        ),
        "analysis_hint": (
            "Look for high-frequency failures from single IPs (brute force), failures for "
            "non-existent accounts (enumeration), and failures immediately before a successful "
            "wtmp login (successful brute force). Correlate source IPs with successful logins."
        ),
    },
    "lastlog": {
        "name": "Last Login Records",
        "category": "Authentication",
        "function": "lastlog",
        "description": (
            "Last login timestamp and source for each user account on the system. "
            "Provides a quick overview of account usage recency."
        ),
        "analysis_hint": (
            "Identify accounts with recent logins that should be dormant or disabled. "
            "Compare with wtmp for consistency — discrepancies may indicate log tampering."
        ),
    },
    "users": {
        "name": "User Accounts",
        "category": "Authentication",
        "function": "users",
        "description": (
            "User account information parsed from /etc/passwd and /etc/shadow, including "
            "UIDs, shells, home directories, and password metadata."
        ),
        "analysis_hint": (
            "Flag accounts with UID 0 (root-equivalent), accounts with login shells that "
            "should have /sbin/nologin, recently created accounts (check shadow dates), and "
            "accounts with empty password fields."
        ),
    },
    "groups": {
        "name": "Groups",
        "category": "Authentication",
        "function": "groups",
        "description": (
            "Group definitions from /etc/group including group members. "
            "Shows privilege group membership such as sudo, wheel, and docker."
        ),
        "analysis_hint": (
            "Check membership of privileged groups (sudo, wheel, docker, adm, root). "
            "Flag unexpected users in administrative groups."
        ),
    },
    "sudoers": {
        "name": "Sudoers Config",
        "category": "Authentication",
        "function": "sudoers",
        "description": (
            "Sudo configuration from /etc/sudoers and /etc/sudoers.d/, defining which "
            "users can run which commands with elevated privileges."
        ),
        "analysis_hint": (
            "Flag NOPASSWD entries, overly broad command allowances (ALL), and rules for "
            "unexpected users. Attackers often modify sudoers for passwordless privilege escalation."
        ),
    },
    # -- Network ------------------------------------------------------------
    "network.interfaces": {
        "name": "Network Interfaces",
        "category": "Network",
        "function": "network.interfaces",
        "description": (
            "Network interface configuration including IP addresses, subnets, and interface names. "
            "Provides context for understanding the system's network position."
        ),
        "analysis_hint": (
            "Document all configured interfaces and IPs for correlation with login source IPs "
            "and network artifacts from other systems. Flag unexpected interfaces (tunnels, bridges)."
        ),
    },
    # -- Logs ---------------------------------------------------------------
    "syslog": {
        "name": "Syslog",
        "category": "Logs",
        "function": "syslog",
        "description": (
            "System log entries from /var/log/syslog, /var/log/messages, and /var/log/auth.log. "
            "Central log source for authentication, service, and kernel events on Linux."
        ),
        "analysis_hint": (
            "Filter for sshd, sudo, su, and PAM messages to reconstruct authentication activity. "
            "Look for service start/stop events, kernel warnings, and log gaps that may indicate "
            "tampering or system downtime."
        ),
    },
    "journalctl": {
        "name": "Systemd Journal",
        "category": "Logs",
        "function": "journalctl",
        "description": (
            "Structured journal entries from systemd-journald, covering services, kernel, and "
            "user-session events with rich metadata."
        ),
        "analysis_hint": (
            "Use unit and priority fields to filter for security-relevant events. "
            "Journal entries complement syslog and may contain structured fields not "
            "present in plain-text logs."
        ),
    },
    "packagemanager": {
        "name": "Package History",
        "category": "Logs",
        "function": "packagemanager",
        "description": (
            "Package installation, removal, and update history from apt, yum, dnf, or other "
            "package managers. Shows software changes over time."
        ),
        "analysis_hint": (
            "Flag recently installed packages, especially compilers (gcc, make), network tools "
            "(nmap, netcat, socat), and packages installed outside normal maintenance windows. "
            "Package removal near incident time may indicate cleanup."
        ),
    },
    # -- SSH ----------------------------------------------------------------
    "ssh.authorized_keys": {
        "name": "SSH Authorized Keys",
        "category": "SSH",
        "function": "ssh.authorized_keys",
        "description": (
            "Per-user authorized_keys files listing public keys allowed for SSH authentication. "
            "A primary persistence mechanism for SSH-based access."
        ),
        "analysis_hint": (
            "Flag keys added recently or for unexpected accounts. Compare key fingerprints "
            "across systems to identify lateral movement. Look for command-restricted keys "
            "and keys with 'from=' options limiting source IPs."
        ),
    },
    "ssh.known_hosts": {
        "name": "SSH Known Hosts",
        "category": "SSH",
        "function": "ssh.known_hosts",
        "description": (
            "Per-user known_hosts files recording SSH server fingerprints the user has connected to. "
            "Reveals outbound SSH connections and lateral movement targets."
        ),
        "analysis_hint": (
            "Identify internal hosts the user SSHed to (lateral movement) and external hosts "
            "(potential C2 or data exfiltration). Hashed known_hosts entries obscure hostnames "
            "but IP-based entries may still be readable."
        ),
    },
}

_apply_artifact_guidance_from_prompts(LINUX_ARTIFACT_REGISTRY, _LINUX_PROMPTS_DIR)


def get_artifact_registry(os_type: str) -> dict[str, dict[str, str]]:
    """Return the artifact registry appropriate for the given OS type.

    Args:
        os_type: Operating system identifier as returned by Dissect's
            ``target.os`` (e.g. ``"windows"``, ``"linux"``).  The value
            is normalised to lowercase before comparison.

    Returns:
        The OS-specific artifact registry dictionary.  Defaults to
        :data:`WINDOWS_ARTIFACT_REGISTRY` for unrecognised OS types.
    """
    normalized = str(os_type).strip().lower() if os_type else ""
    if normalized == "linux":
        return LINUX_ARTIFACT_REGISTRY
    return WINDOWS_ARTIFACT_REGISTRY
