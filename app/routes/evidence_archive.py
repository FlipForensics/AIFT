"""Archive extraction utilities for evidence intake.

Handles safe extraction of ZIP, tar, and 7z archives during evidence
intake, including path-traversal validation and best-evidence-file
selection for Dissect.

Attributes:
    EVIDENCE_FILE_EXTENSIONS: Frozenset of file extensions recognized as
        forensic evidence files inside extracted archives.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path
from typing import Any, Callable
from zipfile import BadZipFile, ZipFile

import py7zr

__all__ = [
    "EVIDENCE_FILE_EXTENSIONS",
    "extract_archive_members",
    "extract_zip",
    "extract_tar",
    "extract_7z",
]

# Extensions for evidence files we look for inside extracted archives.
EVIDENCE_FILE_EXTENSIONS = frozenset({
    ".e01", ".ex01", ".s01", ".l01",
    ".dd", ".img", ".raw", ".bin", ".iso",
    ".vmdk", ".vhd", ".vhdx", ".vdi", ".qcow2", ".hdd", ".hds",
    ".vmx", ".vbox", ".vmcx", ".ovf", ".ova",
    ".asdf", ".asif", ".ad1",
    ".000", ".001",
})


def extract_archive_members(
    destination: Path,
    members: list[tuple[str, Any]],
    *,
    empty_message: str,
    unsafe_paths_message: str,
    no_files_message: str,
    extract_member: Callable[[Any, Path], None] | None = None,
    extract_all_members: Callable[[list[tuple[Any, Path]]], None] | None = None,
) -> Path:
    """Extract archive members safely and return the best Dissect target path.

    Validates path traversal, extracts, then locates the best evidence file.
    Exactly one of *extract_member* or *extract_all_members* must be provided.

    Args:
        destination: Root directory to extract into.
        members: List of ``(member_name, member_object)`` tuples.
        empty_message: Error for empty archives.
        unsafe_paths_message: Error for path traversal.
        no_files_message: Error when extraction produces no files.
        extract_member: Callback to extract a single member.
        extract_all_members: Callback to extract all members at once.

    Returns:
        Path to the best evidence file or extraction directory.

    Raises:
        ValueError: On empty, unsafe, or failed extraction.
    """
    if (extract_member is None) == (extract_all_members is None):
        raise ValueError("Exactly one extraction callback must be provided.")

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    if not members:
        raise ValueError(empty_message)

    validated_members: list[tuple[Any, Path]] = []
    for member_name, member in members:
        member_path = Path(member_name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise ValueError(unsafe_paths_message)
        target = (root / member_path).resolve()
        if not target.is_relative_to(root):
            raise ValueError(unsafe_paths_message)
        target.parent.mkdir(parents=True, exist_ok=True)
        validated_members.append((member, target))

    if extract_all_members is not None:
        extract_all_members(validated_members)
    else:
        for member, target in validated_members:
            extract_member(member, target)

    files = sorted(path for path in destination.rglob("*") if path.is_file())
    if not files:
        raise ValueError(no_files_message)
    evidence_files = [
        path for path in files if path.suffix.lower() in EVIDENCE_FILE_EXTENSIONS
    ]
    if evidence_files:
        for ef in evidence_files:
            if ef.suffix.lower() == ".e01":
                return ef
        return evidence_files[0]

    top_level_entries: set[str] = set()
    has_top_level_file = False
    for file_path in files:
        relative_parts = file_path.relative_to(destination).parts
        if not relative_parts:
            continue
        top_level_entries.add(relative_parts[0])
        if len(relative_parts) == 1:
            has_top_level_file = True

    if not has_top_level_file and len(top_level_entries) == 1:
        wrapper_dir = destination / sorted(top_level_entries)[0]
        if wrapper_dir.is_dir():
            return wrapper_dir

    return destination


def extract_zip(zip_path: Path, destination: Path) -> Path:
    """Extract a ZIP archive and return the best Dissect target path.

    Args:
        zip_path: Path to the ZIP file.
        destination: Directory to extract into.

    Returns:
        Path to the best evidence file or directory.

    Raises:
        ValueError: If the ZIP is invalid, empty, or contains unsafe paths.
    """
    try:
        with ZipFile(zip_path, "r") as archive:
            members = [(member.filename, member) for member in archive.infolist() if not member.is_dir()]

            def _extract_member(member: Any, target: Path) -> None:
                """Extract a single ZIP member to the target path."""
                with archive.open(member, "r") as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            return extract_archive_members(
                destination,
                members,
                empty_message="Evidence ZIP is empty.",
                unsafe_paths_message="Archive rejected: contains unsafe file paths",
                no_files_message="Evidence ZIP extraction produced no files.",
                extract_member=_extract_member,
            )
    except BadZipFile as error:
        raise ValueError(f"Invalid ZIP evidence file: {zip_path.name}") from error


def extract_tar(tar_path: Path, destination: Path) -> Path:
    """Extract a tar archive and return the best Dissect target path.

    Args:
        tar_path: Path to the tar file.
        destination: Directory to extract into.

    Returns:
        Path to the best evidence file or directory.

    Raises:
        ValueError: If the tar is invalid, empty, or contains unsafe paths.
    """
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            raw_members = archive.getmembers()
            for member in raw_members:
                if member.islnk() or member.issym():
                    raise ValueError("Archive rejected: contains unsafe file paths")
            members = [(member.name, member) for member in raw_members if member.isfile()]

            def _extract_member(member: Any, target: Path) -> None:
                """Extract a single tar member to the target path."""
                src = archive.extractfile(member)
                if src is None:
                    return
                with src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            return extract_archive_members(
                destination,
                members,
                empty_message="Evidence tar archive is empty.",
                unsafe_paths_message="Archive rejected: contains unsafe file paths",
                no_files_message="Evidence tar extraction produced no files.",
                extract_member=_extract_member,
            )
    except tarfile.TarError as error:
        raise ValueError(f"Invalid tar evidence file: {tar_path.name}") from error


def extract_7z(archive_path: Path, destination: Path) -> Path:
    """Extract a 7z archive and return the best Dissect target path.

    Args:
        archive_path: Path to the 7z file.
        destination: Directory to extract into.

    Returns:
        Path to the best evidence file or directory.

    Raises:
        ValueError: If the 7z is invalid, empty, or contains unsafe paths.
    """
    try:
        with py7zr.SevenZipFile(archive_path, mode="r") as archive:
            members = [(name, name) for name in archive.getnames() if not name.endswith("/")]

            def _extract_members(validated: list[tuple[Any, Path]]) -> None:
                """Extract 7z members via temp directory for path-traversal safety."""
                import tempfile
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp = Path(tmpdir)
                    archive.extractall(path=tmp)
                    for member_name, target in validated:
                        src = tmp / member_name
                        if src.is_file():
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src, target)

            return extract_archive_members(
                destination,
                members,
                empty_message="Evidence 7z archive is empty.",
                unsafe_paths_message="Archive rejected: contains unsafe file paths",
                no_files_message="Evidence 7z extraction produced no files.",
                extract_all_members=_extract_members,
            )
    except py7zr.Bad7zFile as error:
        raise ValueError(f"Invalid 7z evidence file: {archive_path.name}") from error
