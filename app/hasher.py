"""Evidence hashing utilities for forensic integrity verification."""

from __future__ import annotations

from hashlib import md5, sha256
from pathlib import Path
from typing import Callable, Protocol, TypedDict

CHUNK_SIZE = 4 * 1024 * 1024


class HashResult(TypedDict):
    """Hash output produced for one evidence file."""

    sha256: str
    md5: str
    size_bytes: int


class _Hasher(Protocol):
    def update(self, data: bytes, /) -> None: ...
    def hexdigest(self) -> str: ...


def _compute_digests(
    filepath: str | Path,
    hashers: dict[str, _Hasher],
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[dict[str, str], int]:
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
    """Compute SHA-256 and MD5 in a single pass over a file.

    Returns {"sha256": str, "md5": str, "size_bytes": int}.
    Calls progress_callback(bytes_read, total_bytes) after each chunk if provided.
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
    """Compute the SHA-256 hash for a file."""
    digests, _ = _compute_digests(filepath, {"sha256": sha256()})
    return digests["sha256"]


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
