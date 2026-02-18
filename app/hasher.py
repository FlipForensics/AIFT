"""Evidence hashing utilities for forensic integrity verification."""

from __future__ import annotations

from hashlib import md5, sha256
from pathlib import Path
from typing import Callable, TypedDict

CHUNK_SIZE = 8 * 1024


class HashResult(TypedDict):
    """Hash output produced for one evidence file."""

    sha256: str
    md5: str
    size_bytes: int


def compute_hashes(
    filepath: str | Path,
    progress_callback: Callable[[int, int], None] | None = None,
) -> HashResult:
    """Compute SHA-256 and MD5 in a single pass over a file.

    Returns {"sha256": str, "md5": str, "size_bytes": int}.
    Calls progress_callback(bytes_read, total_bytes) after each chunk if provided.
    """
    path = Path(filepath)
    total_bytes = path.stat().st_size

    sha256_hasher = sha256()
    md5_hasher = md5()
    bytes_read = 0

    if progress_callback is not None:
        progress_callback(0, total_bytes)

    with path.open("rb") as evidence_file:
        while True:
            chunk = evidence_file.read(CHUNK_SIZE)
            if not chunk:
                break

            sha256_hasher.update(chunk)
            md5_hasher.update(chunk)
            bytes_read += len(chunk)

            if progress_callback is not None:
                progress_callback(bytes_read, total_bytes)

    return {
        "sha256": sha256_hasher.hexdigest(),
        "md5": md5_hasher.hexdigest(),
        "size_bytes": total_bytes,
    }


def compute_sha256(filepath: str | Path) -> str:
    """Compute the SHA-256 hash for a file."""
    path = Path(filepath)
    sha256_hasher = sha256()

    with path.open("rb") as evidence_file:
        while True:
            chunk = evidence_file.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256_hasher.update(chunk)

    return sha256_hasher.hexdigest()


def verify_hash(
    filepath: str | Path,
    expected_sha256: str,
    return_computed: bool = False,
) -> bool | tuple[bool, str]:
    """Recompute SHA-256 for a file and compare to an expected hash.

    When ``return_computed`` is True, returns ``(match, computed_sha256)``.
    """
    computed_sha256 = compute_sha256(filepath)
    matches = computed_sha256 == expected_sha256.strip().lower()
    if return_computed:
        return matches, computed_sha256
    return matches
