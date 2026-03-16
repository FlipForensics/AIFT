"""IOC extraction and prompt-building helpers for the forensic analyzer.

Extracts Indicators of Compromise (URLs, IPs, domains, hashes, emails,
file paths, filenames, suspicious tool keywords) from investigation context
text, and formats them into prompt sections for AI analysis.

Attributes:
    LOGGER: Module-level logger instance.
"""

from __future__ import annotations

from .analyzer_constants import (
    DOMAIN_EXCLUDED_SUFFIXES,
    IOC_DOMAIN_RE,
    IOC_EMAIL_RE,
    IOC_FILENAME_RE,
    IOC_HASH_RE,
    IOC_IPV4_RE,
    IOC_URL_RE,
    KNOWN_MALICIOUS_TOOL_KEYWORDS,
    WINDOWS_PATH_RE,
)
from .analyzer_utils import (
    extract_url_host,
    stringify_value,
    truncate_for_prompt,
    unique_preserve_order,
)

__all__ = [
    "extract_ioc_targets",
    "format_ioc_targets",
    "build_priority_directives",
    "build_artifact_final_context_reminder",
    "extract_tool_keywords",
]


def extract_tool_keywords(text: str) -> list[str]:
    """Extract known malicious tool keyword matches from text.

    Args:
        text: Free-text string to scan for tool keywords.

    Returns:
        A deduplicated list of matched tool keyword strings, preserving
        the order of first occurrence.
    """
    lowered = text.lower()
    hits: list[str] = []
    for keyword in KNOWN_MALICIOUS_TOOL_KEYWORDS:
        if keyword in lowered:
            hits.append(keyword)
    return unique_preserve_order(hits)


def extract_ioc_targets(investigation_context: str) -> dict[str, list[str]]:
    """Extract Indicators of Compromise from investigation context text.

    Uses regex patterns to identify URLs, IPv4 addresses, domains,
    hashes (MD5/SHA1/SHA256), email addresses, Windows file paths,
    executable filenames, and known malicious tool keywords.

    Args:
        investigation_context: Free-text investigation context string.

    Returns:
        A dict mapping IOC category names to deduplicated lists of
        extracted values.  Returns an empty dict if no IOCs are found.
    """
    text = stringify_value(investigation_context)
    if not text:
        return {}

    urls = unique_preserve_order(IOC_URL_RE.findall(text))
    ips = unique_preserve_order(IOC_IPV4_RE.findall(text))
    hashes = unique_preserve_order(IOC_HASH_RE.findall(text))
    emails = unique_preserve_order(IOC_EMAIL_RE.findall(text))
    windows_paths = unique_preserve_order(WINDOWS_PATH_RE.findall(text))
    file_names = unique_preserve_order(IOC_FILENAME_RE.findall(text))
    file_names_lower = {value.lower() for value in file_names}
    tools = extract_tool_keywords(text)

    domain_candidates = unique_preserve_order(IOC_DOMAIN_RE.findall(text))
    domains: list[str] = []
    url_hosts = {extract_url_host(url) for url in urls}
    for domain in domain_candidates:
        lowered = domain.lower()
        if lowered in url_hosts:
            continue
        if lowered in file_names_lower:
            continue
        if any(lowered.endswith(suffix) for suffix in DOMAIN_EXCLUDED_SUFFIXES):
            continue
        domains.append(domain)
    domains = unique_preserve_order(domains)

    iocs: dict[str, list[str]] = {}
    if urls:
        iocs["URLs"] = urls
    if ips:
        iocs["IPv4"] = ips
    if domains:
        iocs["Domains"] = domains
    if hashes:
        iocs["Hashes"] = hashes
    if emails:
        iocs["Emails"] = emails
    if windows_paths:
        iocs["FilePaths"] = windows_paths
    if file_names:
        iocs["FileNames"] = file_names
    if tools:
        iocs["SuspiciousTools"] = tools
    return iocs


def format_ioc_targets(investigation_context: str) -> str:
    """Format extracted IOC targets as a human-readable bullet list.

    Args:
        investigation_context: Free-text investigation context string.

    Returns:
        A multi-line string with one bullet per IOC category (up to
        20 values each), or a message indicating no IOCs were found.
    """
    ioc_map = extract_ioc_targets(investigation_context)
    if not ioc_map:
        return "No explicit IOC patterns were extracted from the investigation context."

    lines = []
    for category, values in ioc_map.items():
        limited = values[:20]
        suffix = "" if len(values) <= 20 else " ... [truncated]"
        lines.append(f"- {category}: {', '.join(limited)}{suffix}")
    return "\n".join(lines)


def build_priority_directives(investigation_context: str) -> str:
    """Build numbered priority directives for the AI analysis prompt.

    Generates a set of directives that instruct the AI to prioritize
    the user's investigation context, check IOCs, and run standard
    DFIR checks.

    Args:
        investigation_context: Free-text investigation context string.

    Returns:
        A multi-line numbered list of priority directives.
    """
    ioc_map = extract_ioc_targets(investigation_context)
    has_iocs = bool(ioc_map)
    lines = [
        "1. Treat the user investigation context as highest priority and address it before generic hunting.",
        (
            "2. For each IOC listed below, explicitly classify it as Observed, Not Observed, or Not Assessable "
            "in this artifact."
            if has_iocs
            else "2. No explicit IOC was extracted; still prioritize user-stated hypotheses and suspicious themes."
        ),
        "3. Always run default DFIR checks: privilege escalation, credential access tooling (including Mimikatz-like activity), persistence, defense evasion, lateral movement, and potential exfiltration.",
        "4. Focus on evidence that improves triage or containment decisions; keep baseline/statistical context secondary.",
    ]
    return "\n".join(lines)


def build_artifact_final_context_reminder(
    artifact_key: str,
    artifact_name: str,
    investigation_context: str,
) -> str:
    """Build a short end-of-prompt reminder that survives left-side truncation.

    Places critical context (artifact identity, investigation focus, IOC
    targets, DFIR checks) at the very end of the prompt so that models
    with left-side attention decay still see the most important instructions.

    Args:
        artifact_key: Unique identifier for the artifact.
        artifact_name: Human-readable artifact name.
        investigation_context: The user's investigation context text.

    Returns:
        A multi-line reminder section string starting with a Markdown
        heading.
    """
    context_text = stringify_value(investigation_context)
    if context_text:
        context_text = truncate_for_prompt(context_text, limit=1200)
    else:
        context_text = "No investigation context provided."

    ioc_targets = format_ioc_targets(investigation_context)
    ioc_targets = truncate_for_prompt(ioc_targets, limit=1200)

    lines = [
        "## Final Context Reminder (Do Not Ignore)",
        f"- Artifact key: {artifact_key}",
        f"- Artifact name: {artifact_name}",
        f"- Investigation context (mandatory): {context_text}",
        f"- IOC targets (mandatory follow-through): {ioc_targets}",
        "- Always run default DFIR checks: privilege escalation, credential-access/Mimikatz-like behavior, malicious program execution, persistence/evasion/lateral movement/exfiltration.",
        "- If evidence is insufficient, mark IOC or DFIR check as Not Assessable.",
    ]
    return "\n".join(lines)
