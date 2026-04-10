"""Tests for multi-image route endpoints.

Validates the new image management endpoints (add, list, image-specific
evidence intake and parsing) as well as backward compatibility of legacy
case-level endpoints.
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from app import create_app
from app.case_logging import unregister_all_case_log_handlers
import app.routes as routes
import app.routes.handlers as routes_handlers
import app.routes.evidence as routes_evidence
import app.routes.images as routes_images
import app.routes.tasks as routes_tasks
import app.routes.state as routes_state


class ImmediateThread:
    """Execute thread target synchronously for deterministic testing."""

    def __init__(
        self,
        group: object | None = None,
        target: object | None = None,
        name: str | None = None,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        daemon: bool | None = None,
    ) -> None:
        """Store the target and arguments."""
        del group, name, daemon
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self) -> None:
        """Run the target synchronously."""
        if callable(self._target):
            self._target(*self._args, **self._kwargs)


class FakeParser:
    """Fake ForensicParser for testing without real evidence files."""

    def __init__(
        self,
        evidence_path: str | Path,
        case_dir: str | Path,
        audit_logger: object,
        parsed_dir: str | Path | None = None,
    ) -> None:
        """Initialise with paths."""
        del evidence_path, audit_logger
        self.case_dir = Path(case_dir)
        self.parsed_dir = Path(parsed_dir) if parsed_dir is not None else self.case_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)
        self.os_type = "windows"

    def __enter__(self) -> "FakeParser":
        """Enter context manager."""
        return self

    def __exit__(self, *args: object) -> bool:
        """Exit context manager."""
        return False

    def close(self) -> None:
        """Close the parser."""
        pass

    def get_image_metadata(self) -> dict[str, str]:
        """Return fake image metadata."""
        return {
            "hostname": "test-host",
            "os_version": "Windows 10",
            "domain": "test.local",
        }

    def get_available_artifacts(self) -> list[dict[str, object]]:
        """Return fake available artifacts."""
        return [
            {"key": "runkeys", "name": "Run/RunOnce Keys", "available": True},
            {"key": "services", "name": "Services", "available": True},
        ]

    def parse_artifact(self, artifact_key: str, progress_callback: object | None = None) -> dict[str, object]:
        """Fake-parse an artifact."""
        if callable(progress_callback):
            progress_callback({"artifact_key": artifact_key, "record_count": 1})
        csv_path = self.parsed_dir / f"{artifact_key}.csv"
        csv_path.write_text("name\nvalue\n", encoding="utf-8")
        return {
            "csv_path": str(csv_path),
            "record_count": 1,
            "duration_seconds": 0.01,
            "success": True,
            "error": None,
        }


FAKE_HASHES = {
    "sha256": "a" * 64,
    "md5": "b" * 32,
    "size_bytes": 4,
}


class MultiImageRoutesTests(unittest.TestCase):
    """Test suite for multi-image route endpoints."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = TemporaryDirectory(prefix="aift-multiimage-test-")
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
        """Clean up test fixtures."""
        unregister_all_case_log_handlers()
        self.temp_dir.cleanup()

    def _patch_context(self):
        """Return a combined patch context manager for all fakes."""
        from contextlib import ExitStack
        stack = ExitStack()
        # Patch CASES_ROOT everywhere.
        for mod in (routes, routes_handlers, routes_state, routes_images):
            stack.enter_context(patch.object(mod, "CASES_ROOT", self.cases_root))
        # Patch ForensicParser (images.py uses deferred import from evidence).
        for mod in (routes, routes_handlers, routes_tasks, routes_evidence):
            stack.enter_context(patch.object(mod, "ForensicParser", FakeParser))
        stack.enter_context(patch("app.parser.ForensicParser", FakeParser))
        # Patch compute_hashes (images.py uses deferred import from evidence).
        for mod in (routes, routes_handlers, routes_evidence):
            stack.enter_context(patch.object(mod, "compute_hashes", return_value=dict(FAKE_HASHES)))
        stack.enter_context(patch("app.hasher.compute_hashes", return_value=dict(FAKE_HASHES)))
        # Patch threading.
        stack.enter_context(patch.object(routes.threading, "Thread", ImmediateThread))
        return stack

    def _create_case(self, name: str = "Test Case") -> str:
        """Create a case and return the case_id."""
        resp = self.client.post("/api/cases", json={"case_name": name})
        self.assertEqual(resp.status_code, 201)
        return resp.get_json()["case_id"]

    def test_create_case_creates_images_directory(self) -> None:
        """POST /api/cases creates the images/ subdirectory."""
        with self._patch_context():
            case_id = self._create_case()
            case_dir = self.cases_root / case_id
            self.assertTrue((case_dir / "images").is_dir())
            self.assertTrue((case_dir / "reports").is_dir())

    def test_add_image(self) -> None:
        """POST /api/cases/<id>/images adds an image slot."""
        with self._patch_context():
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/images",
                json={"label": "Workstation-PC01"},
            )
            self.assertEqual(resp.status_code, 201)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertIn("image_id", data)
            self.assertEqual(data["label"], "Workstation-PC01")

            # Verify the directory was created.
            image_dir = self.cases_root / case_id / "images" / data["image_id"]
            self.assertTrue(image_dir.is_dir())
            self.assertTrue((image_dir / "evidence").is_dir())
            self.assertTrue((image_dir / "parsed").is_dir())
            self.assertTrue((image_dir / "metadata.json").is_file())

    def test_add_image_case_not_found(self) -> None:
        """POST /api/cases/<bad_id>/images returns 404."""
        with self._patch_context():
            resp = self.client.post(
                "/api/cases/nonexistent/images",
                json={"label": "test"},
            )
            self.assertEqual(resp.status_code, 404)

    def test_list_images(self) -> None:
        """GET /api/cases/<id>/images lists all images."""
        with self._patch_context():
            case_id = self._create_case()
            # Add two images.
            r1 = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC01"})
            r2 = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC02"})
            self.assertEqual(r1.status_code, 201)
            self.assertEqual(r2.status_code, 201)

            resp = self.client.get(f"/api/cases/{case_id}/images")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(len(data["images"]), 2)
            labels = {img["label"] for img in data["images"]}
            self.assertIn("PC01", labels)
            self.assertIn("PC02", labels)

    def test_list_images_empty(self) -> None:
        """GET /api/cases/<id>/images returns empty list for new case."""
        with self._patch_context():
            case_id = self._create_case()
            resp = self.client.get(f"/api/cases/{case_id}/images")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json()["images"], [])

    def test_image_specific_evidence_intake(self) -> None:
        """POST /api/cases/<id>/images/<img_id>/evidence ingests evidence."""
        evidence_path = Path(self.temp_dir.name) / "test.E01"
        evidence_path.write_bytes(b"test-evidence")

        with self._patch_context():
            case_id = self._create_case()
            add_resp = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC01"})
            image_id = add_resp.get_json()["image_id"]

            resp = self.client.post(
                f"/api/cases/{case_id}/images/{image_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["image_id"], image_id)
            self.assertEqual(data["metadata"]["hostname"], "test-host")
            self.assertEqual(data["os_type"], "windows")

            # Verify metadata.json was updated.
            meta_path = self.cases_root / case_id / "images" / image_id / "metadata.json"
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual(meta["hostname"], "test-host")
            self.assertEqual(meta["os_type"], "windows")

    def test_image_evidence_not_found(self) -> None:
        """POST evidence for nonexistent image returns 404."""
        with self._patch_context():
            case_id = self._create_case()
            resp = self.client.post(
                f"/api/cases/{case_id}/images/nonexistent/evidence",
                json={"path": "/fake/path.E01"},
            )
            self.assertEqual(resp.status_code, 404)

    def test_image_specific_parse(self) -> None:
        """POST /api/cases/<id>/images/<img_id>/parse starts parsing."""
        evidence_path = Path(self.temp_dir.name) / "test.E01"
        evidence_path.write_bytes(b"test-evidence")

        with self._patch_context():
            case_id = self._create_case()
            add_resp = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC01"})
            image_id = add_resp.get_json()["image_id"]

            # Load evidence first.
            ev_resp = self.client.post(
                f"/api/cases/{case_id}/images/{image_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            # Start parsing.
            parse_resp = self.client.post(
                f"/api/cases/{case_id}/images/{image_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)
            data = parse_resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["image_id"], image_id)

            # Verify CSV was created in the image-specific parsed dir.
            parsed_dir = self.cases_root / case_id / "images" / image_id / "parsed"
            csv_files = list(parsed_dir.glob("*.csv"))
            self.assertTrue(len(csv_files) > 0, "Expected at least one CSV file in parsed dir")

    def test_image_parse_progress_sse(self) -> None:
        """GET /api/cases/<id>/images/<img_id>/parse/progress streams SSE."""
        evidence_path = Path(self.temp_dir.name) / "test.E01"
        evidence_path.write_bytes(b"test-evidence")

        with self._patch_context():
            case_id = self._create_case()
            add_resp = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC01"})
            image_id = add_resp.get_json()["image_id"]

            ev_resp = self.client.post(
                f"/api/cases/{case_id}/images/{image_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/images/{image_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            sse_resp = self.client.get(f"/api/cases/{case_id}/images/{image_id}/parse/progress")
            self.assertEqual(sse_resp.status_code, 200)
            sse_text = sse_resp.get_data(as_text=True)
            self.assertIn("parse_completed", sse_text)

    def test_backward_compat_evidence_creates_default_image(self) -> None:
        """POST /api/cases/<id>/evidence auto-creates a default image."""
        evidence_path = Path(self.temp_dir.name) / "test.E01"
        evidence_path.write_bytes(b"test-evidence")

        with self._patch_context():
            case_id = self._create_case()

            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["metadata"]["hostname"], "test-host")

            # Verify an image was auto-created.
            images_dir = self.cases_root / case_id / "images"
            image_dirs = [d for d in images_dir.iterdir() if d.is_dir()]
            self.assertTrue(len(image_dirs) > 0, "Expected a default image directory to be created")

    def test_backward_compat_parse_delegates(self) -> None:
        """POST /api/cases/<id>/parse delegates to image-specific parse."""
        evidence_path = Path(self.temp_dir.name) / "test.E01"
        evidence_path.write_bytes(b"test-evidence")

        with self._patch_context():
            case_id = self._create_case()

            # Use the backward-compat evidence endpoint.
            ev_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            # Now the case should have image_states populated.
            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)
            data = parse_resp.get_json()
            self.assertTrue(data["success"])

    def test_backward_compat_parse_progress(self) -> None:
        """GET /api/cases/<id>/parse/progress works via backward compat."""
        evidence_path = Path(self.temp_dir.name) / "test.E01"
        evidence_path.write_bytes(b"test-evidence")

        with self._patch_context():
            case_id = self._create_case()

            ev_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            sse_resp = self.client.get(f"/api/cases/{case_id}/parse/progress")
            self.assertEqual(sse_resp.status_code, 200)

    def test_multiple_images_workflow(self) -> None:
        """Full workflow: create case -> add 2 images -> evidence each."""
        ev1 = Path(self.temp_dir.name) / "pc01.E01"
        ev2 = Path(self.temp_dir.name) / "pc02.E01"
        ev1.write_bytes(b"evidence-1")
        ev2.write_bytes(b"evidence-2")

        with self._patch_context():
            case_id = self._create_case("Multi-Image Test")

            # Add two images.
            r1 = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC01"})
            r2 = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC02"})
            img1 = r1.get_json()["image_id"]
            img2 = r2.get_json()["image_id"]

            # Load evidence for each.
            e1 = self.client.post(
                f"/api/cases/{case_id}/images/{img1}/evidence",
                json={"path": str(ev1)},
            )
            e2 = self.client.post(
                f"/api/cases/{case_id}/images/{img2}/evidence",
                json={"path": str(ev2)},
            )
            self.assertEqual(e1.status_code, 200)
            self.assertEqual(e2.status_code, 200)

            # List images -- should show both.
            list_resp = self.client.get(f"/api/cases/{case_id}/images")
            self.assertEqual(len(list_resp.get_json()["images"]), 2)

            # Parse for each image.
            p1 = self.client.post(
                f"/api/cases/{case_id}/images/{img1}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(p1.status_code, 202)

            p2 = self.client.post(
                f"/api/cases/{case_id}/images/{img2}/parse",
                json={"artifacts": ["services"]},
            )
            self.assertEqual(p2.status_code, 202)

            # Verify CSVs in separate directories.
            csv1 = self.cases_root / case_id / "images" / img1 / "parsed" / "runkeys.csv"
            csv2 = self.cases_root / case_id / "images" / img2 / "parsed" / "services.csv"
            self.assertTrue(csv1.is_file(), f"Expected {csv1} to exist")
            self.assertTrue(csv2.is_file(), f"Expected {csv2} to exist")

    def test_add_image_empty_label(self) -> None:
        """Adding an image with no label uses empty string."""
        with self._patch_context():
            case_id = self._create_case()
            resp = self.client.post(f"/api/cases/{case_id}/images", json={})
            self.assertEqual(resp.status_code, 201)
            self.assertEqual(resp.get_json()["label"], "")

    def test_parse_no_evidence_returns_400(self) -> None:
        """Parsing an image with no evidence loaded returns 400."""
        with self._patch_context():
            case_id = self._create_case()
            add_resp = self.client.post(f"/api/cases/{case_id}/images", json={"label": "PC01"})
            image_id = add_resp.get_json()["image_id"]

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/images/{image_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 400)
            self.assertIn("No evidence", parse_resp.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
