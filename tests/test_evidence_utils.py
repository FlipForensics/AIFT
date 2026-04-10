"""Unit tests for the shared evidence-handling utilities module.

Validates :func:`~app.routes.evidence_utils.compute_evidence_hashes`,
:func:`~app.routes.evidence_utils.should_skip_hashing`, and
:func:`~app.routes.evidence_utils.open_dissect_target`.

These functions were extracted from duplicated code in the evidence and
images route modules in commit 943849a.  Tests here ensure the shared
implementations behave identically to the originals.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import create_app
from app.routes.evidence_utils import (
    compute_evidence_hashes,
    open_dissect_target,
    should_skip_hashing,
)


# ---------------------------------------------------------------------------
# compute_evidence_hashes
# ---------------------------------------------------------------------------


class TestComputeEvidenceHashes(unittest.TestCase):
    """Tests for the ``compute_evidence_hashes`` utility."""

    def test_skip_hashing_returns_na_placeholders(self) -> None:
        """When skip_hashing is True, hashes are 'N/A (skipped)'."""
        hashes, file_hashes = compute_evidence_hashes(
            files_to_hash=[],
            source_path=Path("test.E01"),
            skip_hashing=True,
        )
        self.assertEqual(hashes["sha256"], "N/A (skipped)")
        self.assertEqual(hashes["md5"], "N/A (skipped)")
        self.assertEqual(hashes["size_bytes"], 0)
        self.assertEqual(hashes["filename"], "test.E01")
        self.assertEqual(file_hashes, [])

    def test_empty_files_returns_directory_placeholders(self) -> None:
        """Empty files_to_hash returns 'N/A (directory)' placeholders."""
        hashes, file_hashes = compute_evidence_hashes(
            files_to_hash=[],
            source_path=Path("evidence_dir"),
            skip_hashing=False,
        )
        self.assertEqual(hashes["sha256"], "N/A (directory)")
        self.assertEqual(hashes["md5"], "N/A (directory)")
        self.assertEqual(hashes["filename"], "evidence_dir")
        self.assertEqual(file_hashes, [])

    @patch("app.hasher.compute_hashes")
    def test_single_file_hashes(self, mock_compute: MagicMock) -> None:
        """Single file returns its hash directly (not wrapped in summary)."""
        mock_compute.return_value = {
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "size_bytes": 1024,
        }
        hashes, file_hashes = compute_evidence_hashes(
            files_to_hash=["/path/to/file.E01"],
            source_path=Path("file.E01"),
            skip_hashing=False,
        )
        self.assertEqual(hashes["sha256"], "a" * 64)
        self.assertEqual(hashes["md5"], "b" * 32)
        self.assertEqual(hashes["size_bytes"], 1024)
        self.assertEqual(hashes["filename"], "file.E01")
        self.assertEqual(len(file_hashes), 1)
        self.assertEqual(file_hashes[0]["path"], "/path/to/file.E01")

    @patch("app.hasher.compute_hashes")
    def test_multiple_files_summary(self, mock_compute: MagicMock) -> None:
        """Multiple files produce a summary with combined size."""
        mock_compute.side_effect = [
            {"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 100},
            {"sha256": "c" * 64, "md5": "d" * 32, "size_bytes": 200},
        ]
        hashes, file_hashes = compute_evidence_hashes(
            files_to_hash=["/f1.E01", "/f2.E02"],
            source_path=Path("f1.E01"),
            skip_hashing=False,
        )
        # Summary uses first file's hashes.
        self.assertEqual(hashes["sha256"], "a" * 64)
        self.assertEqual(hashes["md5"], "b" * 32)
        # Size is summed.
        self.assertEqual(hashes["size_bytes"], 300)
        self.assertEqual(hashes["filename"], "f1.E01")
        self.assertEqual(len(file_hashes), 2)

    def test_skip_hashing_ignores_files_list(self) -> None:
        """Even with files provided, skip_hashing=True returns placeholders."""
        hashes, file_hashes = compute_evidence_hashes(
            files_to_hash=["/some/file.E01"],
            source_path=Path("file.E01"),
            skip_hashing=True,
        )
        self.assertEqual(hashes["sha256"], "N/A (skipped)")
        self.assertEqual(file_hashes, [])


# ---------------------------------------------------------------------------
# should_skip_hashing
# ---------------------------------------------------------------------------


class TestShouldSkipHashing(unittest.TestCase):
    """Tests for ``should_skip_hashing`` within a Flask request context."""

    def setUp(self) -> None:
        """Create a minimal Flask app for request context testing."""
        self.app = create_app()
        self.app.testing = True

    def test_json_skip_hashing_true(self) -> None:
        """JSON body with skip_hashing=true returns True."""
        with self.app.test_request_context(
            "/test",
            method="POST",
            json={"skip_hashing": True},
        ):
            self.assertTrue(should_skip_hashing())

    def test_json_skip_hashing_false(self) -> None:
        """JSON body with skip_hashing=false returns False."""
        with self.app.test_request_context(
            "/test",
            method="POST",
            json={"skip_hashing": False},
        ):
            self.assertFalse(should_skip_hashing())

    def test_json_no_skip_hashing_key(self) -> None:
        """JSON body without skip_hashing returns False."""
        with self.app.test_request_context(
            "/test",
            method="POST",
            json={"path": "/some/path"},
        ):
            self.assertFalse(should_skip_hashing())

    def test_no_body_returns_false(self) -> None:
        """Request with no body returns False."""
        with self.app.test_request_context("/test", method="POST"):
            self.assertFalse(should_skip_hashing())

    def test_multipart_skip_hashing(self) -> None:
        """Multipart form with skip_hashing field returns True."""
        with self.app.test_request_context(
            "/test",
            method="POST",
            content_type="multipart/form-data",
            data={"skip_hashing": "1"},
        ):
            self.assertTrue(should_skip_hashing())


# ---------------------------------------------------------------------------
# open_dissect_target
# ---------------------------------------------------------------------------


class TestOpenDissectTarget(unittest.TestCase):
    """Tests for ``open_dissect_target``."""

    @patch("app.parser.ForensicParser")
    def test_success_returns_metadata(self, mock_parser_cls: MagicMock) -> None:
        """Successful open returns metadata, artifacts, and os_type."""
        mock_parser = MagicMock()
        mock_parser.__enter__ = MagicMock(return_value=mock_parser)
        mock_parser.__exit__ = MagicMock(return_value=False)
        mock_parser.get_image_metadata.return_value = {
            "hostname": "WS01",
            "os_version": "Windows 10",
            "domain": "CORP",
        }
        mock_parser.get_available_artifacts.return_value = [
            {"key": "runkeys", "available": True},
        ]
        mock_parser.os_type = "windows"
        mock_parser_cls.return_value = mock_parser

        metadata, artifacts, os_type = open_dissect_target(
            dissect_path=Path("/fake/path.E01"),
            case_dir=Path("/fake/case"),
            audit_logger=MagicMock(),
            case_id="test-case-id",
        )

        self.assertEqual(metadata["hostname"], "WS01")
        self.assertEqual(os_type, "windows")
        self.assertEqual(len(artifacts), 1)

    @patch("app.parser.ForensicParser")
    def test_failure_returns_degraded_defaults(self, mock_parser_cls: MagicMock) -> None:
        """When ForensicParser raises, degraded defaults are returned."""
        mock_parser_cls.side_effect = RuntimeError("Cannot open evidence")

        metadata, artifacts, os_type = open_dissect_target(
            dissect_path=Path("/fake/path.E01"),
            case_dir=Path("/fake/case"),
            audit_logger=MagicMock(),
            case_id="test-case-id",
        )

        self.assertEqual(metadata["hostname"], "Unknown")
        self.assertEqual(metadata["os_version"], "Unknown")
        self.assertEqual(metadata["domain"], "Unknown")
        self.assertEqual(artifacts, [])
        self.assertEqual(os_type, "unknown")


if __name__ == "__main__":
    unittest.main()
