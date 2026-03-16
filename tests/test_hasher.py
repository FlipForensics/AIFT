from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from app.hasher import compute_hashes, verify_hash


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


    def test_compute_hashes_known_content_produces_correct_digests(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "known.bin"
            test_file.write_bytes(b"AIFT forensic test data")

            result = compute_hashes(test_file)

        import hashlib

        expected_sha256 = hashlib.sha256(b"AIFT forensic test data").hexdigest()
        expected_md5 = hashlib.md5(b"AIFT forensic test data").hexdigest()
        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(result["md5"], expected_md5)
        self.assertEqual(result["size_bytes"], len(b"AIFT forensic test data"))

    def test_progress_callback_is_called_with_bytes_and_total(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "progress.bin"
            content = b"x" * 1024
            test_file.write_bytes(content)

            calls: list[tuple[int, int]] = []

            def on_progress(bytes_read: int, total_bytes: int) -> None:
                calls.append((bytes_read, total_bytes))

            compute_hashes(test_file, progress_callback=on_progress)

        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[0], (0, 1024))
        self.assertEqual(calls[-1][0], 1024)
        self.assertEqual(calls[-1][1], 1024)


class VerifyHashTests(unittest.TestCase):
    def test_verify_hash_passes_with_correct_hash(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"evidence data")

            result = compute_hashes(test_file)
            self.assertTrue(verify_hash(test_file, result["sha256"]))

    def test_verify_hash_fails_with_wrong_hash(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"evidence data")

            self.assertFalse(verify_hash(test_file, "0" * 64))

    def test_verify_hash_returns_computed_when_requested(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"evidence data")

            expected = compute_hashes(test_file)["sha256"]
            matches, computed = verify_hash(test_file, expected, return_computed=True)

        self.assertTrue(matches)
        self.assertEqual(computed, expected)

    def test_verify_hash_return_computed_on_mismatch(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"evidence data")

            matches, computed = verify_hash(test_file, "bad" * 16, return_computed=True)

        self.assertFalse(matches)
        self.assertIsInstance(computed, str)
        self.assertEqual(len(computed), 64)

    def test_verify_hash_is_case_insensitive(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"case test")

            expected = compute_hashes(test_file)["sha256"].upper()
            self.assertTrue(verify_hash(test_file, expected))


if __name__ == "__main__":
    unittest.main()
