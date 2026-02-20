from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from app.hasher import compute_hashes


class HasherTests(unittest.TestCase):
    def test_compute_hashes_missing_file_raises_file_not_found_error(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            missing_path = Path(temp_dir) / "missing.bin"
            with self.assertRaises(FileNotFoundError):
                compute_hashes(missing_path)

    def test_compute_hashes_empty_file_returns_expected_digests(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            empty_file = Path(temp_dir) / "empty.bin"
            empty_file.write_bytes(b"")

            result = compute_hashes(empty_file)

        self.assertEqual(
            result["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(result["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(result["size_bytes"], 0)

    def test_compute_hashes_permission_denied_raises_permission_error(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            protected_file = Path(temp_dir) / "protected.bin"
            protected_file.write_bytes(b"top-secret")
            original_open = Path.open

            def deny_read(self: Path, mode: str = "r", *args: object, **kwargs: object) -> object:
                if self == protected_file and "r" in mode:
                    raise PermissionError(f"Permission denied: {self}")
                return original_open(self, mode, *args, **kwargs)

            with patch("pathlib.Path.open", autospec=True, side_effect=deny_read):
                with self.assertRaises(PermissionError):
                    compute_hashes(protected_file)


if __name__ == "__main__":
    unittest.main()
