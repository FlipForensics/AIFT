"""Tests for the skip-hashing option during evidence intake.

Verifies that:
- Evidence intake respects the ``skip_hashing`` flag for both path and
  upload modes.
- Hashes are set to ``"N/A (skipped)"`` when hashing is skipped.
- The report endpoint handles skipped hashing without attempting
  verification.
- The audit trail records the skipped state.
- ``ReportGenerator._resolve_hash_verification`` returns the correct
  ``"SKIPPED"`` label.

Attributes:
    FAKE_SHA256: Placeholder SHA-256 digest used in non-skip tests.
    FAKE_MD5: Placeholder MD5 digest used in non-skip tests.
"""
from __future__ import annotations

import json
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app import create_app
from app.case_logging import unregister_all_case_log_handlers
from app.reporter import ReportGenerator
from tests.conftest import FakeParser, FakeReportGenerator, FAKE_HASHES
import app.routes as routes
import app.routes.evidence as routes_evidence
import app.routes.handlers as routes_handlers
import app.routes.images as routes_images
import app.routes.state as routes_state
import app.routes.tasks as routes_tasks

FAKE_SHA256 = FAKE_HASHES["sha256"]
FAKE_MD5 = FAKE_HASHES["md5"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _standard_patches(cases_root: Path):
    """Return a contextmanager stack of common mock patches.

    Args:
        cases_root: Temporary cases root directory.

    Returns:
        A combined context-manager that patches parsers, generators,
        hash helpers, and ``CASES_ROOT`` across all route modules.
    """
    from contextlib import ExitStack

    stack = ExitStack()
    for mod in (routes, routes_handlers, routes_images, routes_state):
        stack.enter_context(patch.object(mod, "CASES_ROOT", cases_root))
    for mod in (routes, routes_handlers, routes_tasks, routes_evidence):
        stack.enter_context(patch.object(mod, "ForensicParser", FakeParser))
    stack.enter_context(patch("app.parser.ForensicParser", FakeParser))
    for mod in (routes, routes_handlers, routes_evidence):
        stack.enter_context(patch.object(mod, "ReportGenerator", FakeReportGenerator))
    for mod in (routes, routes_handlers, routes_evidence):
        stack.enter_context(patch.object(
            mod, "compute_hashes",
            return_value={"sha256": FAKE_SHA256, "md5": FAKE_MD5, "size_bytes": 4},
        ))
    stack.enter_context(patch(
        "app.hasher.compute_hashes",
        return_value={"sha256": FAKE_SHA256, "md5": FAKE_MD5, "size_bytes": 4},
    ))
    for mod in (routes, routes_handlers, routes_evidence):
        stack.enter_context(patch.object(
            mod, "verify_hash", return_value=(True, FAKE_SHA256),
        ))
    return stack


def _create_report_generator(cases_root: Path) -> ReportGenerator:
    """Instantiate a ``ReportGenerator`` pointing at the real templates.

    Args:
        cases_root: Temporary cases root directory.

    Returns:
        A ``ReportGenerator`` ready for testing.
    """
    templates_dir = Path(__file__).resolve().parents[1] / "templates"
    return ReportGenerator(templates_dir=templates_dir, cases_root=cases_root)


# ---------------------------------------------------------------------------
# Route-level tests
# ---------------------------------------------------------------------------

class TestSkipHashingIntake(unittest.TestCase):
    """Evidence intake with ``skip_hashing`` flag."""

    def setUp(self) -> None:
        """Set up a Flask test client and temporary directories."""
        self.temp_dir = TemporaryDirectory(prefix="aift-skip-hash-test-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.csrf_token = self.app.config["CSRF_TOKEN"]
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.csrf_token
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()
        routes.CHAT_PROGRESS.clear()
        unregister_all_case_log_handlers()

    def tearDown(self) -> None:
        """Clean up temporary resources."""
        unregister_all_case_log_handlers()
        self.temp_dir.cleanup()

    def _create_case(self) -> str:
        """Create a case and return its ID.

        Returns:
            The UUID string of the new case.
        """
        resp = self.client.post("/api/cases", json={"case_name": "Skip Hash Test"})
        self.assertEqual(resp.status_code, 201)
        return resp.get_json()["case_id"]

    # -- Path mode tests ---------------------------------------------------

    def test_path_mode_skip_hashing_sets_na(self) -> None:
        """Path mode with skip_hashing=true stores 'N/A (skipped)' hashes."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": True},
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["hashes"]["sha256"], "N/A (skipped)")
        self.assertEqual(data["hashes"]["md5"], "N/A (skipped)")

    def test_path_mode_skip_hashing_does_not_call_compute_hashes(self) -> None:
        """Hash computation is not invoked when skip_hashing is set."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root) as stack:
            compute_mock = stack.enter_context(
                patch.object(routes_evidence, "compute_hashes",
                             return_value={"sha256": FAKE_SHA256, "md5": FAKE_MD5, "size_bytes": 4})
            )
            case_id = self._create_case()
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": True},
            )

        compute_mock.assert_not_called()

    def test_path_mode_without_skip_hashing_computes_hashes(self) -> None:
        """Normal intake (no skip) computes real hashes."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["hashes"]["sha256"], FAKE_SHA256)
        self.assertEqual(data["hashes"]["md5"], FAKE_MD5)

    def test_path_mode_skip_hashing_false_computes_hashes(self) -> None:
        """Explicitly passing skip_hashing=false still computes hashes."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": False},
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["hashes"]["sha256"], FAKE_SHA256)

    # -- Upload mode tests -------------------------------------------------

    def test_upload_mode_skip_hashing_sets_na(self) -> None:
        """Upload mode with skip_hashing=1 stores 'N/A (skipped)' hashes."""
        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": (BytesIO(b"demo"), "sample.E01"),
                    "skip_hashing": "1",
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["hashes"]["sha256"], "N/A (skipped)")
        self.assertEqual(data["hashes"]["md5"], "N/A (skipped)")

    def test_upload_mode_without_skip_hashing_computes_hashes(self) -> None:
        """Upload mode without the flag computes real hashes."""
        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": (BytesIO(b"demo"), "sample.E01"),
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["hashes"]["sha256"], FAKE_SHA256)

    # -- Case state tests --------------------------------------------------

    def test_skip_hashing_stores_empty_file_hashes(self) -> None:
        """When hashing is skipped, evidence_file_hashes is empty."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": True},
            )
            with routes.STATE_LOCK:
                file_hashes = routes.CASE_STATES[case_id].get("evidence_file_hashes", [])
                ev_hashes = routes.CASE_STATES[case_id].get("evidence_hashes", {})

        self.assertEqual(file_hashes, [])
        self.assertEqual(ev_hashes["sha256"], "N/A (skipped)")

    # -- Audit trail tests -------------------------------------------------

    def test_skip_hashing_audit_trail(self) -> None:
        """Audit log records 'N/A (skipped)' for sha256 when hashing is skipped."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": True},
            )

        audit_path = self.cases_root / case_id / "audit.jsonl"
        entries = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        intake_events = [e for e in entries if e.get("action") == "evidence_intake"]
        self.assertTrue(intake_events)
        details = intake_events[-1].get("details", {})
        self.assertEqual(details["sha256"], "N/A (skipped)")
        self.assertEqual(details["md5"], "N/A (skipped)")
        self.assertEqual(details["evidence_file_hashes"], [])


class TestSkipHashingReport(unittest.TestCase):
    """Report generation when hashing was skipped during intake."""

    def setUp(self) -> None:
        """Set up a Flask test client and temporary directories."""
        self.temp_dir = TemporaryDirectory(prefix="aift-skip-hash-report-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.csrf_token = self.app.config["CSRF_TOKEN"]
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.csrf_token
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()
        routes.CHAT_PROGRESS.clear()
        unregister_all_case_log_handlers()

    def tearDown(self) -> None:
        """Clean up temporary resources."""
        unregister_all_case_log_handlers()
        self.temp_dir.cleanup()

    def _create_case(self) -> str:
        """Create a case and return its ID.

        Returns:
            The UUID string of the new case.
        """
        resp = self.client.post("/api/cases", json={"case_name": "Skip Hash Report"})
        self.assertEqual(resp.status_code, 201)
        return resp.get_json()["case_id"]

    def test_report_succeeds_when_hashing_was_skipped(self) -> None:
        """Report generation succeeds without hash verification when hashing was skipped."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root) as stack:
            verify_mock = stack.enter_context(
                patch.object(routes_evidence, "verify_hash", return_value=(True, FAKE_SHA256))
            )

            case_id = self._create_case()
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": True},
            )

            # Inject analysis results so the report guard passes.
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["analysis_results"] = {
                    "summary": "Test summary",
                    "per_artifact": [{"artifact_name": "runkeys", "analysis": "Found entries."}],
                }

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)
            self.assertEqual(report_resp.mimetype, "text/html")

            # verify_hash must NOT be called when hashing was skipped.
            verify_mock.assert_not_called()

    def test_report_audit_records_skipped_hash_verification(self) -> None:
        """Audit trail records skipped=true for hash_verification when hashing was skipped."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root):
            case_id = self._create_case()
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path), "skip_hashing": True},
            )

            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["analysis_results"] = {
                    "summary": "Test summary",
                    "per_artifact": [{"artifact_name": "runkeys", "analysis": "Found entries."}],
                }

            self.client.get(f"/api/cases/{case_id}/report")

        audit_path = self.cases_root / case_id / "audit.jsonl"
        entries = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        hash_events = [e for e in entries if e.get("action") == "hash_verification"]
        self.assertTrue(hash_events)
        details = hash_events[-1].get("details", {})
        self.assertTrue(details.get("skipped"))
        self.assertTrue(details.get("match"))

    def test_normal_intake_report_still_verifies_hashes(self) -> None:
        """Report generation with normal intake still calls verify_hash."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with _standard_patches(self.cases_root) as stack:
            verify_mock = stack.enter_context(
                patch.object(routes_evidence, "verify_hash", return_value=(True, FAKE_SHA256))
            )

            case_id = self._create_case()
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )

            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["analysis_results"] = {
                    "summary": "Test summary",
                    "per_artifact": [{"artifact_name": "runkeys", "analysis": "Found entries."}],
                }

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)

            # verify_hash MUST be called for normal (non-skipped) intake.
            verify_mock.assert_called()


# ---------------------------------------------------------------------------
# ReportGenerator unit tests
# ---------------------------------------------------------------------------

class TestResolveHashVerificationSkipped(unittest.TestCase):
    """Tests for ``_resolve_hash_verification`` with the skipped state."""

    def setUp(self) -> None:
        """Create a ReportGenerator instance for testing."""
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_skipped_string_returns_skipped_label(self) -> None:
        """The string ``'skipped'`` produces a SKIPPED label."""
        result = self.gen._resolve_hash_verification({"hash_verified": "skipped"})
        self.assertTrue(result["passed"])
        self.assertTrue(result.get("skipped"))
        self.assertEqual(result["label"], "SKIPPED")

    def test_skipped_string_case_insensitive(self) -> None:
        """The skipped check is case-insensitive."""
        for val in ("skipped", "SKIPPED", "Skipped"):
            result = self.gen._resolve_hash_verification({"hash_verified": val})
            self.assertEqual(result["label"], "SKIPPED", f"Failed for value: {val}")
            self.assertTrue(result.get("skipped"), f"Missing skipped flag for: {val}")

    def test_skipped_detail_mentions_user_request(self) -> None:
        """The detail string explains that the user opted out."""
        result = self.gen._resolve_hash_verification({"hash_verified": "skipped"})
        self.assertIn("skipped", result["detail"].lower())

    def test_skipped_does_not_fall_through_to_sha_check(self) -> None:
        """Even with SHA-256 keys present, 'skipped' takes priority."""
        result = self.gen._resolve_hash_verification({
            "hash_verified": "skipped",
            "expected_sha256": "a" * 64,
            "reverified_sha256": "b" * 64,
        })
        self.assertEqual(result["label"], "SKIPPED")
        self.assertTrue(result["passed"])

    def test_bool_true_still_returns_pass(self) -> None:
        """Boolean ``True`` still returns PASS (not SKIPPED)."""
        result = self.gen._resolve_hash_verification({"hash_verified": True})
        self.assertTrue(result["passed"])
        self.assertEqual(result["label"], "PASS")
        self.assertFalse(result.get("skipped", False))

    def test_bool_false_still_returns_fail(self) -> None:
        """Boolean ``False`` still returns FAIL."""
        result = self.gen._resolve_hash_verification({"hash_verified": False})
        self.assertFalse(result["passed"])
        self.assertEqual(result["label"], "FAIL")

    def test_empty_dict_still_returns_fail(self) -> None:
        """An empty dict still returns FAIL (unchanged behaviour)."""
        result = self.gen._resolve_hash_verification({})
        self.assertFalse(result["passed"])
        self.assertEqual(result["label"], "FAIL")


if __name__ == "__main__":
    unittest.main()
