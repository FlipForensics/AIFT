from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
import unittest

from app.hasher import (
    CHUNK_SIZE,
    _compute_digests,
    compute_hashes,
    compute_sha256,
    verify_hash,
)


class ChunkSizeTests(unittest.TestCase):
    """Verify the CHUNK_SIZE module-level constant."""

    def test_chunk_size_is_four_mib(self) -> None:
        self.assertEqual(CHUNK_SIZE, 4 * 1024 * 1024)


class ComputeDigestsTests(unittest.TestCase):
    """Tests for the internal _compute_digests helper."""

    def test_single_hasher_returns_correct_digest(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "single.bin"
            content = b"hello forensics"
            test_file.write_bytes(content)

            digests, total = _compute_digests(
                test_file, {"sha256": hashlib.sha256()}
            )

        self.assertEqual(total, len(content))
        self.assertEqual(digests["sha256"], hashlib.sha256(content).hexdigest())

    def test_multiple_hashers_all_computed(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "multi.bin"
            content = b"multi-hash test"
            test_file.write_bytes(content)

            digests, total = _compute_digests(
                test_file,
                {"sha256": hashlib.sha256(), "md5": hashlib.md5()},
            )

        self.assertEqual(digests["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(digests["md5"], hashlib.md5(content).hexdigest())
        self.assertEqual(total, len(content))

    def test_no_callback_does_not_raise(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "nocb.bin"
            test_file.write_bytes(b"data")

            digests, total = _compute_digests(
                test_file, {"md5": hashlib.md5()}, progress_callback=None
            )

        self.assertEqual(total, 4)
        self.assertIn("md5", digests)

    def test_callback_receives_zero_then_final(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "cb.bin"
            test_file.write_bytes(b"abcdef")

            calls: list[tuple[int, int]] = []
            _compute_digests(
                test_file,
                {"md5": hashlib.md5()},
                progress_callback=lambda br, tb: calls.append((br, tb)),
            )

        self.assertEqual(calls[0], (0, 6))
        self.assertEqual(calls[-1], (6, 6))

    def test_accepts_string_path(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "strpath.bin"
            test_file.write_bytes(b"string path input")

            digests, total = _compute_digests(
                str(test_file), {"sha256": hashlib.sha256()}
            )

        self.assertEqual(total, len(b"string path input"))
        self.assertIsInstance(digests["sha256"], str)

    def test_empty_file_returns_empty_digest(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "empty.bin"
            test_file.write_bytes(b"")

            digests, total = _compute_digests(
                test_file, {"sha256": hashlib.sha256()}
            )

        self.assertEqual(total, 0)
        self.assertEqual(
            digests["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_large_file_multiple_chunks(self) -> None:
        """Ensure files larger than CHUNK_SIZE are read in multiple passes."""
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "large.bin"
            # Write slightly more than one chunk so we get at least two reads
            content = b"\xab" * (CHUNK_SIZE + 1024)
            test_file.write_bytes(content)

            calls: list[tuple[int, int]] = []
            digests, total = _compute_digests(
                test_file,
                {"sha256": hashlib.sha256()},
                progress_callback=lambda br, tb: calls.append((br, tb)),
            )

        self.assertEqual(total, len(content))
        self.assertEqual(digests["sha256"], hashlib.sha256(content).hexdigest())
        # initial 0 call + at least 2 chunk calls
        self.assertGreaterEqual(len(calls), 3)

    def test_missing_file_raises(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            missing = Path(temp_dir) / "nope.bin"
            with self.assertRaises((FileNotFoundError, OSError)):
                _compute_digests(missing, {"sha256": hashlib.sha256()})


class ComputeHashesTests(unittest.TestCase):
    """Tests for the public compute_hashes function."""

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

    def test_compute_hashes_with_string_path(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "strpath.bin"
            content = b"string path evidence"
            test_file.write_bytes(content)

            result = compute_hashes(str(test_file))

        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["md5"], hashlib.md5(content).hexdigest())
        self.assertEqual(result["size_bytes"], len(content))

    def test_compute_hashes_returns_typed_dict_keys(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "keys.bin"
            test_file.write_bytes(b"check keys")

            result = compute_hashes(test_file)

        self.assertIn("sha256", result)
        self.assertIn("md5", result)
        self.assertIn("size_bytes", result)
        self.assertEqual(len(result), 3)

    def test_compute_hashes_without_callback(self) -> None:
        """Ensure no error when progress_callback is omitted (default None)."""
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "nocb.bin"
            test_file.write_bytes(b"no callback")

            result = compute_hashes(test_file)

        self.assertEqual(result["size_bytes"], len(b"no callback"))


class ComputeSha256Tests(unittest.TestCase):
    """Tests for the compute_sha256 convenience function."""

    def test_returns_correct_sha256(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "sha.bin"
            content = b"sha256 only"
            test_file.write_bytes(content)

            digest = compute_sha256(test_file)

        self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_returns_string(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "sha_type.bin"
            test_file.write_bytes(b"type check")

            digest = compute_sha256(test_file)

        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)

    def test_empty_file(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "empty.bin"
            test_file.write_bytes(b"")

            digest = compute_sha256(test_file)

        self.assertEqual(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_accepts_string_path(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "str.bin"
            content = b"string input"
            test_file.write_bytes(content)

            digest = compute_sha256(str(test_file))

        self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_missing_file_raises(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            missing = Path(temp_dir) / "gone.bin"
            with self.assertRaises(FileNotFoundError):
                compute_sha256(missing)


class VerifyHashTests(unittest.TestCase):
    """Tests for the verify_hash function."""

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

    def test_verify_hash_strips_whitespace(self) -> None:
        """The expected hash is .strip()'d, so leading/trailing spaces should work."""
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"strip test")

            expected = compute_hashes(test_file)["sha256"]
            padded = f"  {expected}  \n"
            self.assertTrue(verify_hash(test_file, padded))

    def test_verify_hash_uppercase_with_whitespace(self) -> None:
        """Combined case: uppercase + whitespace in expected hash."""
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"combo test")

            expected = compute_hashes(test_file)["sha256"].upper()
            padded = f" {expected} "
            self.assertTrue(verify_hash(test_file, padded))

    def test_verify_hash_default_return_is_bool(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"bool check")

            expected = compute_hashes(test_file)["sha256"]
            result = verify_hash(test_file, expected)

        self.assertIsInstance(result, bool)

    def test_verify_hash_return_computed_is_tuple(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            test_file = Path(temp_dir) / "verify.bin"
            test_file.write_bytes(b"tuple check")

            expected = compute_hashes(test_file)["sha256"]
            result = verify_hash(test_file, expected, return_computed=True)

        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_verify_hash_missing_file_raises(self) -> None:
        with TemporaryDirectory(prefix="aift-hasher-test-") as temp_dir:
            missing = Path(temp_dir) / "gone.bin"
            with self.assertRaises(FileNotFoundError):
                verify_hash(missing, "a" * 64)


if __name__ == "__main__":
    unittest.main()
