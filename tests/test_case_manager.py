"""Unit tests for :mod:`app.case_manager`."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.case_manager import CaseManager


class TestCaseManagerCreateCase(unittest.TestCase):
    """Tests for CaseManager.create_case."""

    def test_create_case_returns_uuid(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case("Test Case")
            self.assertIsInstance(case_id, str)
            self.assertEqual(len(case_id), 36)  # UUID format

    def test_create_case_creates_directories(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            case_dir = Path(tmp) / case_id
            self.assertTrue(case_dir.is_dir())
            self.assertTrue((case_dir / "images").is_dir())
            self.assertTrue((case_dir / "reports").is_dir())

    def test_create_case_initialises_audit(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case("Audit Test")
            audit_file = Path(tmp) / case_id / "audit.jsonl"
            self.assertTrue(audit_file.is_file())
            entries = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["action"], "case_created")
            self.assertEqual(entries[0]["details"]["case_name"], "Audit Test")


class TestCaseManagerAddImage(unittest.TestCase):
    """Tests for CaseManager.add_image."""

    def test_add_image_returns_uuid(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id, label="disk1.E01")
            self.assertEqual(len(image_id), 36)

    def test_add_image_creates_subdirectories(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id, label="disk1.E01")
            image_dir = Path(tmp) / case_id / "images" / image_id
            self.assertTrue((image_dir / "evidence").is_dir())
            self.assertTrue((image_dir / "parsed").is_dir())
            self.assertTrue((image_dir / "parsed_deduplicated").is_dir())

    def test_add_image_writes_metadata(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id, label="suspect.E01")
            meta_file = Path(tmp) / case_id / "images" / image_id / "metadata.json"
            self.assertTrue(meta_file.is_file())
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            self.assertEqual(meta["image_id"], image_id)
            self.assertEqual(meta["label"], "suspect.E01")
            self.assertIn("created", meta)

    def test_add_image_logs_audit(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id, label="disk1.E01")
            audit_file = Path(tmp) / case_id / "audit.jsonl"
            entries = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            image_entries = [e for e in entries if e["action"] == "image_added"]
            self.assertEqual(len(image_entries), 1)
            self.assertEqual(image_entries[0]["details"]["image_id"], image_id)

    def test_add_image_nonexistent_case_raises(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            with self.assertRaises(FileNotFoundError):
                cm.add_image("nonexistent-case-id")


class TestCaseManagerDeleteImage(unittest.TestCase):
    """Tests for CaseManager.delete_image."""

    def test_delete_image_removes_directory(self) -> None:
        """Deleting an image removes its directory and contents."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id, label="to-delete.E01")
            image_dir = Path(tmp) / case_id / "images" / image_id
            self.assertTrue(image_dir.is_dir())

            result = cm.delete_image(case_id, image_id)
            self.assertEqual(result, image_id)
            self.assertFalse(image_dir.exists())

    def test_delete_image_logs_audit(self) -> None:
        """Deleting an image writes an image_deleted audit entry."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id, label="audit-del.E01")
            cm.delete_image(case_id, image_id)

            audit_file = Path(tmp) / case_id / "audit.jsonl"
            entries = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            del_entries = [e for e in entries if e["action"] == "image_deleted"]
            self.assertEqual(len(del_entries), 1)
            self.assertEqual(del_entries[0]["details"]["image_id"], image_id)

    def test_delete_image_nonexistent_image_raises(self) -> None:
        """Deleting a non-existent image raises FileNotFoundError."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            with self.assertRaises(FileNotFoundError):
                cm.delete_image(case_id, "nonexistent-image-id")

    def test_delete_image_nonexistent_case_raises(self) -> None:
        """Deleting from a non-existent case raises FileNotFoundError."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            with self.assertRaises(FileNotFoundError):
                cm.delete_image("nonexistent-case-id", "some-image-id")


class TestCaseManagerGetCaseInfo(unittest.TestCase):
    """Tests for CaseManager.get_case_info."""

    def test_get_case_info_nonexistent_case_raises(self) -> None:
        """Querying info for a non-existent case raises FileNotFoundError."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            with self.assertRaises(FileNotFoundError):
                cm.get_case_info("nonexistent-case-id")

    def test_get_case_info_returns_all_images(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            img1 = cm.add_image(case_id, label="disk1.E01")
            img2 = cm.add_image(case_id, label="disk2.E01")

            info = cm.get_case_info(case_id)
            self.assertEqual(info["case_id"], case_id)
            image_ids = {img["image_id"] for img in info["images"]}
            self.assertIn(img1, image_ids)
            self.assertIn(img2, image_ids)
            self.assertEqual(len(info["images"]), 2)

    def test_get_case_info_empty_case(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            info = cm.get_case_info(case_id)
            self.assertEqual(info["images"], [])


class TestCaseManagerGetImageDir(unittest.TestCase):
    """Tests for CaseManager.get_image_dir."""

    def test_get_image_dir_returns_path(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            image_id = cm.add_image(case_id)
            result = cm.get_image_dir(case_id, image_id)
            self.assertIsInstance(result, Path)
            self.assertTrue(result.is_dir())

    def test_get_image_dir_nonexistent_image_raises(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            with self.assertRaises(FileNotFoundError):
                cm.get_image_dir(case_id, "nonexistent-image-id")


class TestCaseManagerLegacy(unittest.TestCase):
    """Tests for legacy case detection and migration."""

    @staticmethod
    def _create_legacy_case(base: Path, case_id: str) -> Path:
        """Create a fake legacy case directory with flat structure."""
        case_dir = base / case_id
        case_dir.mkdir(parents=True)
        (case_dir / "evidence").mkdir()
        (case_dir / "parsed").mkdir()
        # Note: parsed_deduplicated may or may not exist in legacy cases
        # Write a marker file into evidence and parsed
        (case_dir / "evidence" / "disk.E01").write_text("fake evidence")
        (case_dir / "parsed" / "evtx.csv").write_text("ts,msg\n2025-01-01,hello")
        return case_dir

    def test_is_legacy_case_true(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            case_id = "legacy-case-001"
            self._create_legacy_case(Path(tmp), case_id)
            cm = CaseManager(tmp)
            self.assertTrue(cm.is_legacy_case(case_id))

    def test_is_legacy_case_false(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            self.assertFalse(cm.is_legacy_case(case_id))

    def test_migrate_legacy_case(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            case_id = "legacy-migrate-001"
            self._create_legacy_case(Path(tmp), case_id)
            cm = CaseManager(tmp)

            image_id = cm.migrate_legacy_case(case_id)
            case_dir = Path(tmp) / case_id

            # Legacy dirs should be gone from root
            self.assertFalse((case_dir / "evidence").is_dir())
            self.assertFalse((case_dir / "parsed").is_dir())

            # Data should be under images/<image_id>/
            image_dir = case_dir / "images" / image_id
            self.assertTrue((image_dir / "evidence").is_dir())
            self.assertTrue((image_dir / "parsed").is_dir())
            self.assertTrue((image_dir / "parsed_deduplicated").is_dir())

            # Files should be preserved
            self.assertTrue((image_dir / "evidence" / "disk.E01").is_file())
            self.assertEqual(
                (image_dir / "evidence" / "disk.E01").read_text(),
                "fake evidence",
            )
            self.assertTrue((image_dir / "parsed" / "evtx.csv").is_file())

            # Metadata should exist
            meta = json.loads(
                (image_dir / "metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(meta["image_id"], image_id)
            self.assertEqual(meta["label"], "migrated")

            # reports/ should exist
            self.assertTrue((case_dir / "reports").is_dir())

    def test_migrate_legacy_case_logs_audit(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            case_id = "legacy-audit-001"
            self._create_legacy_case(Path(tmp), case_id)
            cm = CaseManager(tmp)
            cm.migrate_legacy_case(case_id)

            audit_file = Path(tmp) / case_id / "audit.jsonl"
            entries = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            migration_entries = [
                e for e in entries if e["action"] == "legacy_case_migrated"
            ]
            self.assertEqual(len(migration_entries), 1)

    def test_migrate_non_legacy_case_raises(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            with self.assertRaises(ValueError):
                cm.migrate_legacy_case(case_id)

    def test_is_legacy_case_false_after_migration(self) -> None:
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            case_id = "legacy-check-002"
            self._create_legacy_case(Path(tmp), case_id)
            cm = CaseManager(tmp)
            self.assertTrue(cm.is_legacy_case(case_id))
            cm.migrate_legacy_case(case_id)
            self.assertFalse(cm.is_legacy_case(case_id))


class TestCaseManagerPathTraversal(unittest.TestCase):
    """Tests for path traversal protection."""

    def test_case_id_path_traversal_raises(self) -> None:
        """A case_id containing '..' must raise ValueError."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            # Create a directory outside cases_dir that the traversal
            # would reach, so the guard fires before FileNotFoundError.
            (Path(tmp).parent / "evil").mkdir(exist_ok=True)
            with self.assertRaises((ValueError, FileNotFoundError)):
                cm.get_case_info("../evil")

    def test_image_id_path_traversal_raises(self) -> None:
        """An image_id containing '..' must raise ValueError."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            with self.assertRaises((ValueError, FileNotFoundError)):
                cm.get_image_dir(case_id, "../../etc")

    def test_delete_image_path_traversal_raises(self) -> None:
        """delete_image with traversal image_id must raise ValueError."""
        with TemporaryDirectory(prefix="aift-cm-") as tmp:
            cm = CaseManager(tmp)
            case_id = cm.create_case()
            with self.assertRaises((ValueError, FileNotFoundError)):
                cm.delete_image(case_id, "../../etc")


if __name__ == "__main__":
    unittest.main()
