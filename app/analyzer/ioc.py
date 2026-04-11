"""IOC extraction and prompt-building helpers for the forensic analyzer.

Extracts Indicators of Compromise (URLs, IPs, domains, hashes, emails,
file paths, filenames, suspicious tool keywords) from investigation context
text, and formats them into prompt sections for AI analysis.

Includes false-positive filtering to avoid misidentifying GUIDs as hashes
and filenames/version strings as domain names.

Attributes:
    _GUID_HEX_RE: Compiled regex matching 32-char GUID-shaped hex strings.
"""

from __future__ import annotations

from .constants import (
    DOMAIN_EXCLUDED_SUFFIXES,
    DOMAIN_EXCLUDED_TLDS,
    HASH_ID_COLUMN_HINTS,
    IOC_DOMAIN_RE,
    IOC_EMAIL_RE,
    IOC_FILENAME_RE,
    IOC_HASH_RE,
    IOC_IPV4_RE,
    IOC_URL_RE,
    KNOWN_MALICIOUS_TOOL_KEYWORDS,
    WINDOWS_PATH_RE,
)
from .utils import (
    extract_url_host,
    stringify_value,
    truncate_for_prompt,
    unique_preserve_order,
)

import re

__all__ = [
    "extract_ioc_targets",
    "format_ioc_targets",
    "build_priority_directives",
    "build_artifact_final_context_reminder",
    "extract_tool_keywords",
    "is_likely_false_positive_hash",
    "is_likely_false_positive_domain",
]

# Pattern matching GUID format with hyphens: 8-4-4-4-12 hex digits.
_GUID_HYPHENATED_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _collect_guid_hex_set(text: str) -> set[str]:
    """Find all hyphenated GUIDs in text and return their hex-only forms.

    Args:
        text: Source text to scan for GUIDs.

    Returns:
        A set of lowercased 32-char hex strings corresponding to GUIDs
        found in the text (with hyphens removed).
    """
    return {m.replace("-", "").lower() for m in _GUID_HYPHENATED_RE.findall(text)}


def is_likely_false_positive_hash(value: str, guid_hex_set: set[str] | None = None) -> bool:
    """Check whether a hex string is likely a non-IOC false positive.

    Filters out hex strings that correspond to hyphenated GUIDs found in
    the source text, and values that are all zeros or all one repeated
    hex digit (e.g. ``"0" * 64``).

    Args:
        value: A hex string matched by ``IOC_HASH_RE``.
        guid_hex_set: Optional set of lowercase 32-char hex strings derived
            from hyphenated GUIDs in the source text.  When provided,
            32-char matches are checked against this set.

    Returns:
        ``True`` if the value is likely a false positive, ``False`` otherwise.
    """
    # All-zero or single-repeated-digit hashes are placeholders, not IOCs.
    if len(set(value.lower())) <= 1:
        return True
    # If we have a GUID set from the source text, check membership.
    if guid_hex_set and len(value) == 32 and value.lower() in guid_hex_set:
        return True
    return False


def is_likely_false_positive_domain(domain: str) -> bool:
    """Check whether a domain candidate is likely a filename or version string.

    Args:
        domain: A domain candidate string matched by ``IOC_DOMAIN_RE``.

    Returns:
        ``True`` if the domain looks like a filename (ends with a known
        file extension) or a version string (e.g. ``v2.0``), ``False``
        otherwise.
    """
    lowered = domain.lower()
    # Check if the TLD portion matches a known file extension.
    last_dot = lowered.rfind(".")
    if last_dot >= 0:
        suffix = lowered[last_dot:]
        if suffix in DOMAIN_EXCLUDED_TLDS:
            return True
    # Version-string pattern like "v2.0", "1.2.3", "v10.3"
    if re.match(r"^v?\d+(\.\d+)+$", lowered):
        return True
    return False


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
    guid_hex_set = _collect_guid_hex_set(text)
    raw_hashes = unique_preserve_order(IOC_HASH_RE.findall(text))
    hashes = [h for h in raw_hashes if not is_likely_false_positive_hash(h, guid_hex_set)]
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
        if is_likely_false_positive_domain(domain):
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


def format_ioc_targets(
    investigation_context: str,
    ioc_targets: dict[str, list[str]] | None = None,
) -> str:
    """Format extracted IOC targets as a human-readable bullet list.

    Args:
        investigation_context: Free-text investigation context string.
        ioc_targets: Optional pre-extracted IOC dict from
            ``extract_ioc_targets()``.  When provided the function
            skips redundant extraction.  ``None`` (the default) means
            extraction is performed internally for backward
            compatibility.

    Returns:
        A multi-line string with one bullet per IOC category (up to
        20 values each), or a message indicating no IOCs were found.
    """
    ioc_map = ioc_targets if ioc_targets is not None else extract_ioc_targets(investigation_context)
    if not ioc_map:
        return "No explicit IOC patterns were extracted from the investigation context."

    lines = []
    for category, values in ioc_map.items():
        limited = values[:20]
        suffix = "" if len(values) <= 20 else " ... [truncated]"
        lines.append(f"- {category}: {', '.join(limited)}{suffix}")
    return "\n".join(lines)


def build_priority_directives(
    investigation_context: str,
    ioc_targets: dict[str, list[str]] | None = None,
) -> str:
    """Build numbered priority directives for the AI analysis prompt.

    Generates a set of directives that instruct the AI to prioritize
    the user's investigation context, check IOCs, and run standard
    DFIR checks.

    Args:
        investigation_context: Free-text investigation context string.
        ioc_targets: Optional pre-extracted IOC dict from
            ``extract_ioc_targets()``.  When provided the function
            skips redundant extraction.  ``None`` (the default) means
            extraction is performed internally for backward
            compatibility.

    Returns:
        A multi-line numbered list of priority directives.
    """
    ioc_map = ioc_targets if ioc_targets is not None else extract_ioc_targets(investigation_context)
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
    ioc_targets: dict[str, list[str]] | None = None,
) -> str:
    """Build a short end-of-prompt reminder that survives left-side truncation.

    Places critical context (artifact identity, investigation focus, IOC
    targets, DFIR checks) at the very end of the prompt so that models
    with left-side attention decay still see the most important instructions.

    Args:
        artifact_key: Unique identifier for the artifact.
        artifact_name: Human-readable artifact name.
        investigation_context: The user's investigation context text.
        ioc_targets: Optional pre-extracted IOC dict from
            ``extract_ioc_targets()``.  When provided the function
            passes it through to ``format_ioc_targets()`` to skip
            redundant extraction.  ``None`` (the default) means
            extraction is performed internally for backward
            compatibility.

    Returns:
        A multi-line reminder section string starting with a Markdown
        heading.
    """
    context_text = stringify_value(investigation_context)
    if context_text:
        context_text = truncate_for_prompt(context_text, limit=1200)
    else:
        context_text = "No investigation context provided."

    ioc_targets_text = format_ioc_targets(investigation_context, ioc_targets=ioc_targets)
    ioc_targets_text = truncate_for_prompt(ioc_targets_text, limit=1200)

    lines = [
        "## Final Context Reminder (Do Not Ignore)",
        f"- Artifact key: {artifact_key}",
        f"- Artifact name: {artifact_name}",
        f"- Investigation context (mandatory): {context_text}",
        f"- IOC targets (mandatory follow-through): {ioc_targets_text}",
        "- Always run default DFIR checks: privilege escalation, credential-access/Mimikatz-like behavior, malicious program execution, persistence/evasion/lateral movement/exfiltration.",
        "- If evidence is insufficient, mark IOC or DFIR check as Not Assessable.",
    ]
    return "\n".join(lines)
