"""Tests for evidence discovery and path validation in app/automation/discovery.py.

Covers path validation (quote stripping, tilde expansion, traversal rejection,
existence checking) and evidence discovery (single files, directories, segment
deduplication, hidden/system file skipping, archive inclusion, sorting).

Attributes:
    EVIDENCE_EXTENSIONS: Sample extensions used to create test evidence files.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.automation.discovery import discover_evidence, validate_evidence_path


class TestValidateEvidencePath(unittest.TestCase):
    """Tests for validate_evidence_path()."""

    def setUp(self) -> None:
        """Create a temporary directory with a sample file."""
        self.temp_dir = TemporaryDirectory(prefix="aift-disc-test-")
        self.root = Path(self.temp_dir.name)
        self.sample_file = self.root / "evidence.e01"
        self.sample_file.write_bytes(b"")

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_valid_file_path_returns_resolved(self) -> None:
        """Existing file returns resolved absolute Path."""
        result = validate_evidence_path(str(self.sample_file))
        self.assertTrue(result.is_absolute())
        self.assertEqual(result, self.sample_file.resolve())

    def test_valid_directory_returns_resolved(self) -> None:
        """Existing directory returns resolved absolute Path."""
        result = validate_evidence_path(str(self.root))
        self.assertTrue(result.is_absolute())
        self.assertEqual(result, self.root.resolve())

    def test_strips_surrounding_quotes(self) -> None:
        """Quoted paths like '"C:\\path"' are unquoted."""
        quoted = f'"{self.sample_file}"'
        result = validate_evidence_path(quoted)
        self.assertEqual(result, self.sample_file.resolve())

    def test_strips_single_quotes(self) -> None:
        """Single-quoted paths are also unquoted."""
        quoted = f"'{self.sample_file}'"
        result = validate_evidence_path(quoted)
        self.assertEqual(result, self.sample_file.resolve())

    def test_expands_user_home(self) -> None:
        """Tilde paths like ~/evidence expand to home dir."""
        home = Path.home()
        # We can only test that ~ expansion doesn't crash and produces
        # a path under the user's home directory.
        if home.exists():
            with patch.object(Path, "exists", return_value=True):
                result = validate_evidence_path("~/somefile")
                self.assertTrue(str(result).startswith(str(home)))

    def test_rejects_path_traversal(self) -> None:
        """Paths with '..' components raise ValueError."""
        traversal_path = str(self.root / "sub" / ".." / "evidence.e01")
        with self.assertRaises(ValueError) as ctx:
            validate_evidence_path(traversal_path)
        self.assertIn("..", str(ctx.exception))

    def test_nonexistent_path_raises(self) -> None:
        """Missing paths raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            validate_evidence_path(str(self.root / "nonexistent.e01"))

    def test_empty_string_raises(self) -> None:
        """Empty string raises ValueError."""
        with self.assertRaises(ValueError):
            validate_evidence_path("")

    def test_whitespace_only_raises(self) -> None:
        """Whitespace-only string raises ValueError."""
        with self.assertRaises(ValueError):
            validate_evidence_path("   ")


class TestDiscoverEvidence(unittest.TestCase):
    """Tests for discover_evidence()."""

    def setUp(self) -> None:
        """Create a temporary directory for evidence file stubs."""
        self.temp_dir = TemporaryDirectory(prefix="aift-disc-test-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def _touch(self, *parts: str) -> Path:
        """Create an empty file within the temp directory.

        Args:
            *parts: Path components relative to the temp root.

        Returns:
            Resolved Path to the created file.
        """
        p = self.root.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"")
        return p.resolve()

    def test_single_e01_file(self) -> None:
        """Single E01 file returns one-element list."""
        f = self._touch("image.E01")
        result = discover_evidence(f)
        self.assertEqual(result, [f])

    def test_single_vmdk_file(self) -> None:
        """VMDK file is recognized as valid evidence."""
        f = self._touch("disk.vmdk")
        result = discover_evidence(f)
        self.assertEqual(result, [f])

    def test_unsupported_extension_raises(self) -> None:
        """File with .txt extension raises ValueError."""
        f = self._touch("readme.txt")
        with self.assertRaises(ValueError) as ctx:
            discover_evidence(f)
        self.assertIn(".txt", str(ctx.exception))

    def test_directory_with_mixed_files(self) -> None:
        """Directory scan finds evidence files and ignores non-evidence."""
        self._touch("image.e01")
        self._touch("disk.vmdk")
        self._touch("readme.txt")
        self._touch("notes.doc")

        result = discover_evidence(self.root)
        names = [p.name for p in result]
        self.assertIn("image.e01", names)
        self.assertIn("disk.vmdk", names)
        self.assertNotIn("readme.txt", names)
        self.assertNotIn("notes.doc", names)

    def test_directory_includes_subdirectories(self) -> None:
        """Child directories are included as Dissect targets."""
        sub = self.root / "acquire_output"
        sub.mkdir()
        # Put a file inside so it's not empty
        (sub / "data.bin").write_bytes(b"")

        result = discover_evidence(self.root)
        self.assertIn(sub.resolve(), result)

    def test_directory_no_evidence_returns_empty(self) -> None:
        """Directory with no evidence files and no subdirs returns empty."""
        self._touch("readme.txt")
        self._touch("notes.doc")
        result = discover_evidence(self.root)
        self.assertEqual(result, [])

    def test_segment_deduplication(self) -> None:
        """Only first segment of split E01 (image.E01) is returned,
        not image.E02, image.E03, etc."""
        self._touch("image.E01")
        self._touch("image.E02")
        self._touch("image.E03")

        result = discover_evidence(self.root)
        names = [p.name for p in result]
        self.assertIn("image.E01", names)
        self.assertNotIn("image.E02", names)
        self.assertNotIn("image.E03", names)

    def test_hidden_files_skipped(self) -> None:
        """Files starting with '.' are skipped."""
        self._touch(".hidden.e01")
        self._touch("visible.e01")

        result = discover_evidence(self.root)
        names = [p.name for p in result]
        self.assertNotIn(".hidden.e01", names)
        self.assertIn("visible.e01", names)

    def test_system_files_skipped(self) -> None:
        """Thumbs.db, desktop.ini, .DS_Store are skipped."""
        self._touch("Thumbs.db")
        self._touch("desktop.ini")
        self._touch(".DS_Store")
        self._touch("evidence.e01")

        result = discover_evidence(self.root)
        names = [p.name for p in result]
        self.assertNotIn("Thumbs.db", names)
        self.assertNotIn("desktop.ini", names)
        self.assertNotIn(".DS_Store", names)
        self.assertIn("evidence.e01", names)

    def test_archive_files_included(self) -> None:
        """ZIP and 7z files are included as-is."""
        self._touch("backup.zip")
        self._touch("archive.7z")

        result = discover_evidence(self.root)
        names = [p.name for p in result]
        self.assertIn("backup.zip", names)
        self.assertIn("archive.7z", names)

    def test_results_are_sorted(self) -> None:
        """Returned list is sorted by path string."""
        self._touch("zebra.e01")
        self._touch("alpha.e01")
        self._touch("middle.vmdk")

        result = discover_evidence(self.root)
        path_strings = [str(p) for p in result]
        self.assertEqual(path_strings, sorted(path_strings))

    def test_nonexistent_directory_raises(self) -> None:
        """Missing directory raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            discover_evidence(self.root / "does_not_exist")

    def test_empty_directory_returns_empty(self) -> None:
        """Empty directory returns empty list."""
        empty = self.root / "empty"
        empty.mkdir()
        result = discover_evidence(empty)
        self.assertEqual(result, [])

    def test_multiple_segment_groups(self) -> None:
        """Multiple independent segment groups each contribute one entry."""
        self._touch("case_a.E01")
        self._touch("case_a.E02")
        self._touch("case_b.E01")
        self._touch("case_b.E02")
        self._touch("case_b.E03")

        result = discover_evidence(self.root)
        names = [p.name for p in result]
        self.assertIn("case_a.E01", names)
        self.assertIn("case_b.E01", names)
        self.assertNotIn("case_a.E02", names)
        self.assertNotIn("case_b.E02", names)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
