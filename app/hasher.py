"""Evidence hashing utilities for forensic integrity verification.

Provides functions to compute SHA-256 and MD5 digests of evidence files in
a single streaming pass.  These hashes are recorded during evidence intake
and re-verified before report generation to ensure that the evidence has
not been modified during analysis.

The file is read in chunks of :data:`CHUNK_SIZE` bytes to keep memory
usage bounded even for multi-gigabyte disk images.  An optional progress
callback is supported for UI feedback during long-running hash operations.

Attributes:
    CHUNK_SIZE: Number of bytes read per iteration (4 MiB).
"""

from __future__ import annotations

from hashlib import md5, sha256
from pathlib import Path
from typing import Callable, Protocol, TypedDict

__all__ = [
    "compute_hashes",
    "compute_hashes_multi",
    "verify_hash",
    "verify_hashes_multi",
]

CHUNK_SIZE = 4 * 1024 * 1024


class HashResult(TypedDict):
    """Hash output produced for one evidence file."""

    sha256: str
    md5: str
    size_bytes: int


class _Hasher(Protocol):
    """Structural protocol matching :mod:`hashlib` hash objects."""

    def update(self, data: bytes, /) -> None: ...
    def hexdigest(self) -> str: ...


def _compute_digests(
    filepath: str | Path,
    hashers: dict[str, _Hasher],
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[dict[str, str], int]:
    """Stream a file through one or more hash algorithms simultaneously.

    Args:
        filepath: Path to the file to hash.
        hashers: Mapping of algorithm name to hasher instance
            (e.g. ``{"sha256": sha256()}``).
        progress_callback: Optional ``(bytes_read, total_bytes)`` callback
            invoked after each chunk.

    Returns:
        A tuple of ``(digests, total_bytes)`` where *digests* maps each
        algorithm name to its hex digest string.
    """
    path = Path(filepath)
    total_bytes = path.stat().st_size
    bytes_read = 0

    if progress_callback is not None:
        progress_callback(0, total_bytes)

    with path.open("rb") as evidence_file:
        while True:
            chunk = evidence_file.read(CHUNK_SIZE)
            if not chunk:
                break

            for hasher in hashers.values():
                hasher.update(chunk)
            bytes_read += len(chunk)

            if progress_callback is not None:
                progress_callback(bytes_read, total_bytes)

    return {name: hasher.hexdigest() for name, hasher in hashers.items()}, total_bytes


def compute_hashes(
    filepath: str | Path,
    progress_callback: Callable[[int, int], None] | None = None,
) -> HashResult:
    """Compute SHA-256 and MD5 digests in a single streaming pass.

    Args:
        filepath: Path to the evidence file.
        progress_callback: Optional ``(bytes_read, total_bytes)`` callback
            invoked after each 4 MiB chunk for progress reporting.

    Returns:
        A :class:`HashResult` dictionary containing ``sha256``, ``md5``,
        and ``size_bytes`` keys.
    """
    digests, total_bytes = _compute_digests(
        filepath,
        {"sha256": sha256(), "md5": md5()},
        progress_callback=progress_callback,
    )
    return {
        "sha256": digests["sha256"],
        "md5": digests["md5"],
        "size_bytes": total_bytes,
    }


def compute_sha256(filepath: str | Path) -> str:
    """Compute the SHA-256 hex digest for a single file.

    Args:
        filepath: Path to the file to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest string.
    """
    digests, _ = _compute_digests(filepath, {"sha256": sha256()})
    return digests["sha256"]


def verify_hash(
    filepath: str | Path,
    expected_sha256: str,
    return_computed: bool = False,
) -> bool | tuple[bool, str]:
    """Re-compute SHA-256 for a file and compare against an expected value.

    Used before report generation to verify that evidence has not been
    modified since intake.

    Args:
        filepath: Path to the evidence file.
        expected_sha256: The SHA-256 digest recorded at intake.
        return_computed: When *True*, return both the match result and the
            computed digest.

    Returns:
        ``True`` / ``False`` when *return_computed* is *False*, or a tuple
        ``(match, computed_sha256)`` when it is *True*.
    """
    computed_sha256 = compute_sha256(filepath)
    matches = computed_sha256.lower() == expected_sha256.strip().lower()
    if return_computed:
        return matches, computed_sha256
    return matches


def compute_hashes_multi(
    filepaths: list[Path],
    progress_callback: Callable[[int, int], None] | None = None,
) -> list[HashResult]:
    """Compute SHA-256 and MD5 digests for each file in a list.

    Each file is hashed independently via :func:`compute_hashes`.  The
    returned list preserves the input order and augments each result with
    a ``path`` key so the caller can correlate results back to files.

    Args:
        filepaths: List of evidence file paths to hash.
        progress_callback: Optional ``(bytes_read, total_bytes)`` callback
            forwarded to :func:`compute_hashes` for each file.

    Returns:
        A list of :class:`HashResult` dicts, each with an additional
        ``path`` key containing the string representation of the file.
    """
    results: list[HashResult] = []
    for filepath in filepaths:
        result = compute_hashes(filepath, progress_callback)
        result["path"] = str(filepath)  # type: ignore[typeddict-unknown-key]
        results.append(result)
    return results


def verify_hashes_multi(
    file_hash_entries: list[dict[str, str | int]],
) -> tuple[bool, list[dict[str, object]]]:
    """Verify multiple evidence files against their recorded SHA-256 digests.

    Each entry in *file_hash_entries* must have ``path`` and ``sha256``
    keys.  Missing files are reported as failures.

    Args:
        file_hash_entries: List of dicts with ``path`` (str) and
            ``sha256`` (str) keys from intake-time hashing.

    Returns:
        A tuple ``(all_passed, details)`` where *all_passed* is ``True``
        only if every file matches, and *details* is a list of per-file
        result dicts with ``path``, ``match``, ``expected``, and
        ``computed`` keys.
    """
    all_ok = True
    details: list[dict[str, object]] = []
    for entry in file_hash_entries:
        path = Path(str(entry["path"]))
        expected = str(entry["sha256"]).strip().lower()
        if not path.exists():
            details.append({
                "path": str(path),
                "match": False,
                "expected": expected,
                "computed": "FILE_MISSING",
            })
            all_ok = False
            continue
        computed = compute_sha256(path)
        match = computed == expected
        details.append({
            "path": str(path),
            "match": match,
            "expected": expected,
            "computed": computed,
        })
        if not match:
            all_ok = False
    return all_ok, details
