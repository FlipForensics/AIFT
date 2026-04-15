"""HTTP route layer for the AIFT Flask application.

This package contains all HTTP endpoint definitions, in-memory state
management, evidence handling, artifact/profile logic, and background
task runners for the AIFT forensic triage wizard.

Sub-modules:

- ``state``: Constants, global state dicts, SSE streaming, case management.
- ``evidence``: CSV/hash helpers, route handlers, backward-compatible re-exports.
- ``evidence_archive``: Archive extraction (ZIP, tar, 7z).
- ``evidence_upload``: Upload handling and evidence path resolution.
- ``evidence_utils``: Hashing and Dissect target opening utilities.
- ``artifacts``: Artifact option normalisation, profile CRUD, date validation.
- ``tasks``: Background parse/analysis runners and prompt helpers.
- ``tasks_chat``: Background chat runner and chat-specific prompt helpers.
- ``handlers``: Core blueprint (UI, cases, settings) and route registration.
- ``analysis``: AI analysis routes.
- ``chat``: Chat routes.
- ``images``: Multi-image management routes.
"""

from __future__ import annotations

# Re-export the primary entry point used by app/__init__.py.
from .handlers import register_routes

# Re-export names that external code (tests, etc.) accesses via
# ``import app.routes as routes; routes.SOME_NAME``.
#
# State, constants, and helpers:
from .state import (  # noqa: F401
    ANALYSIS_PROGRESS,
    CASE_STATES,
    CASE_TTL_SECONDS,
    CASES_ROOT,
    CHAT_HISTORY_MAX_PAIRS,
    CHAT_PROGRESS,
    CONNECTION_TEST_SYSTEM_PROMPT,
    CONNECTION_TEST_USER_PROMPT,
    DEFAULT_FORENSIC_SYSTEM_PROMPT,
    DISSECT_EVIDENCE_EXTENSIONS,
    IMAGES_ROOT,
    MASKED,
    MODE_PARSE_AND_AI,
    MODE_PARSE_ONLY,
    PARSE_PROGRESS,
    PROJECT_ROOT,
    SAFE_NAME_RE,
    SENSITIVE_KEYS,
    SSE_INITIAL_IDLE_GRACE_SECONDS,
    SSE_POLL_INTERVAL_SECONDS,
    STATE_LOCK,
    TERMINAL_CASE_STATUSES,
    audit_config_change,
    cleanup_case_entries,
    cleanup_terminal_cases,
    deep_merge,
    emit_progress,
    error_response,
    get_case,
    mark_case_status,
    mask_sensitive,
    new_progress,
    normalize_case_status,
    now_iso,
    resolve_logo_filename,
    safe_int,
    safe_name,
    sanitize_changed_keys,
    set_progress_status,
    stream_sse,
    success_response,
)

# Shared evidence utilities:
from .evidence_utils import (  # noqa: F401
    compute_evidence_hashes,
    open_dissect_target,
    should_skip_hashing,
)

# Evidence helpers and blueprint:
from .evidence import (  # noqa: F401
    EWF_SEGMENT_RE,
    SPLIT_RAW_SEGMENT_RE,
    build_csv_map,
    collect_case_csv_paths,
    evidence_bp,
    read_audit_entries,
    resolve_case_csv_output_dir,
    resolve_evidence_payload,
    resolve_hash_verification_path,
)

# Artifact / profile helpers and blueprint:
from .artifacts import (  # noqa: F401
    BUILTIN_RECOMMENDED_PROFILE,
    PROFILE_DIRNAME,
    PROFILE_FILE_SUFFIX,
    PROFILE_NAME_RE,
    RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS,
    artifact_bp,
    artifact_options_to_lists,
    compose_profile_response,
    extract_parse_progress,
    extract_parse_selection_payload,
    load_profiles_from_directory,
    normalize_artifact_mode,
    normalize_artifact_options,
    normalize_profile_name,
    profile_path_for_new_name,
    resolve_profiles_root,
    sanitize_prompt,
    validate_analysis_date_range,
    write_profile_file,
)

# Background task runners:
from .tasks import (  # noqa: F401
    load_case_analysis_results,
    resolve_case_investigation_context,
    resolve_case_parsed_dir,
    run_analysis,
    run_chat,
    run_parse,
    run_task_with_case_log_context,
)

# Re-export names from handlers.py that tests patch directly on ``routes``.
from .handlers import (  # noqa: F401
    WINDOWS_ARTIFACT_REGISTRY,
    ForensicAnalyzer,
    ForensicParser,
    ReportGenerator,
    TOOL_VERSION,
    case_log_context,
    compute_hashes,
    create_provider,
    verify_hash,
    AIProviderError,
    routes_bp,
    threading,
)

# Sub-blueprints (evidence_bp and artifact_bp already imported above):
from .analysis import analysis_bp  # noqa: F401
from .automation import automation_bp  # noqa: F401
from .chat import chat_bp  # noqa: F401
from .images import images_bp  # noqa: F401

__all__ = [
    "register_routes",
    "analysis",
    "artifacts",
    "chat",
    "evidence",
    "handlers",
    "state",
    "tasks",
]
