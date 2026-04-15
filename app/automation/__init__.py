"""Headless automation package for AIFT forensic triage pipelines.

Provides evidence discovery, JSON report export, and an orchestration engine
that runs the complete AIFT workflow without Flask or a browser.

Attributes:
    AutomationRequest: Dataclass describing automation run parameters.
    AutomationResult: Dataclass describing automation run outcomes.
    run_automation: Main entry point for headless pipeline execution.
    discover_evidence: Recursive evidence file scanner.
    validate_evidence_path: Input path sanitiser and validator.
    export_json_report: Structured JSON report writer.
"""

from app.automation.engine import AutomationRequest, AutomationResult, run_automation
from app.automation.discovery import discover_evidence, validate_evidence_path
from app.automation.json_export import export_json_report

__all__ = [
    "AutomationRequest",
    "AutomationResult",
    "run_automation",
    "discover_evidence",
    "validate_evidence_path",
    "export_json_report",
]
