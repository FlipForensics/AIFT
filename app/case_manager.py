"""Case directory management for multi-image forensic triage cases.

Implements the multi-image case directory structure where each case can
contain multiple disk images, each with its own evidence, parsed data,
and deduplication directories.

Directory layout::

    cases/
      <case_id>/
        audit.jsonl
        images/
          <image_id>/
            evidence/
            parsed/
            parsed_deduplicated/
            metadata.json
        reports/

The :class:`CaseManager` handles creation, enumeration, legacy detection,
and migration of case directories.

Attributes:
    logger: Module-level logger for diagnostic messages.
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit import AuditLogger

__all__ = ["CaseManager"]

logger = logging.getLogger(__name__)


def _utc_now_iso8601() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class CaseManager:
    """Manage multi-image forensic case directories.

    Each case is identified by a UUID and stored under a configurable
    base directory.  Within a case, individual disk images are also
    identified by UUIDs and hold their own evidence, parsed output,
    and deduplicated output directories.

    Attributes:
        cases_dir: Resolved :class:`~pathlib.Path` to the base cases
            directory.
    """

    def __init__(self, cases_dir: str | Path = "cases") -> None:
        """Initialise the case manager.

        Args:
            cases_dir: Base directory where all case directories are
                stored.  Created if it does not exist.
        """
        self.cases_dir = Path(cases_dir).resolve()
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Case lifecycle
    # ------------------------------------------------------------------

    def create_case(self, case_name: str | None = None) -> str:
        """Create a new case directory with the multi-image layout.

        Creates the top-level case directory, the ``images/`` and
        ``reports/`` subdirectories, and initialises the ``audit.jsonl``
        file via :class:`~app.audit.AuditLogger`.

        Args:
            case_name: Optional human-readable label for the case.
                Stored in the audit log but not used in the directory
                name.

        Returns:
            The generated case UUID string.
        """
        case_id = str(uuid4())
        case_dir = self.cases_dir / case_id

        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "images").mkdir(exist_ok=True)
        (case_dir / "reports").mkdir(exist_ok=True)

        audit = AuditLogger(case_dir)
        audit.log("case_created", {
            "case_id": case_id,
            "case_name": case_name or "",
        })

        logger.info("Created case %s at %s", case_id, case_dir)
        return case_id

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def add_image(self, case_id: str, label: str | None = None) -> str:
        """Add a new image slot to an existing case.

        Creates the image subdirectory with ``evidence/``, ``parsed/``,
        and ``parsed_deduplicated/`` folders, and writes a
        ``metadata.json`` file.

        Args:
            case_id: UUID of the parent case.
            label: Optional human-readable label for the image (e.g.
                the original filename).

        Returns:
            The generated image UUID string.

        Raises:
            FileNotFoundError: If the case directory does not exist.
        """
        case_dir = self._require_case_dir(case_id)
        images_dir = case_dir / "images"
        images_dir.mkdir(exist_ok=True)

        image_id = str(uuid4())
        image_dir = images_dir / image_id

        image_dir.mkdir(parents=True, exist_ok=True)
        (image_dir / "evidence").mkdir(exist_ok=True)
        (image_dir / "parsed").mkdir(exist_ok=True)
        (image_dir / "parsed_deduplicated").mkdir(exist_ok=True)

        metadata = {
            "label": label or "",
            "image_id": image_id,
            "created": _utc_now_iso8601(),
        }
        (image_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8",
        )

        audit = AuditLogger(case_dir)
        audit.log("image_added", {
            "case_id": case_id,
            "image_id": image_id,
            "label": label or "",
        })

        logger.info("Added image %s to case %s", image_id, case_id)
        return image_id

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_case_info(self, case_id: str) -> dict[str, Any]:
        """Return metadata for a case including its images.

        Args:
            case_id: UUID of the case.

        Returns:
            A dictionary with keys ``case_id``, ``case_dir``, and
            ``images`` (a list of dicts each containing ``image_id``,
            ``label``, and ``created``).

        Raises:
            FileNotFoundError: If the case directory does not exist.
        """
        case_dir = self._require_case_dir(case_id)
        images_dir = case_dir / "images"

        images: list[dict[str, str]] = []
        if images_dir.is_dir():
            for child in sorted(images_dir.iterdir()):
                meta_file = child / "metadata.json"
                if child.is_dir() and meta_file.is_file():
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    images.append({
                        "image_id": meta.get("image_id", child.name),
                        "label": meta.get("label", ""),
                        "created": meta.get("created", ""),
                    })

        return {
            "case_id": case_id,
            "case_dir": str(case_dir),
            "images": images,
        }

    def get_image_dir(self, case_id: str, image_id: str) -> Path:
        """Return the full path to an image's directory.

        Args:
            case_id: UUID of the case.
            image_id: UUID of the image.

        Returns:
            Resolved :class:`~pathlib.Path` to the image directory.

        Raises:
            FileNotFoundError: If the case or image directory does not
                exist.
        """
        case_dir = self._require_case_dir(case_id)
        image_dir = case_dir / "images" / image_id
        if not image_dir.is_dir():
            raise FileNotFoundError(
                f"Image directory not found: {image_dir}"
            )
        return image_dir

    def is_legacy_case(self, case_id: str) -> bool:
        """Check whether a case uses the old flat directory layout.

        A legacy case has ``evidence/`` directly under the case
        directory instead of under ``images/<image_id>/``.

        Args:
            case_id: UUID of the case.

        Returns:
            *True* if the case has a flat ``evidence/`` directory at
            its root level; *False* otherwise.

        Raises:
            FileNotFoundError: If the case directory does not exist.
        """
        case_dir = self._require_case_dir(case_id)
        return (case_dir / "evidence").is_dir()

    # ------------------------------------------------------------------
    # Legacy migration
    # ------------------------------------------------------------------

    def migrate_legacy_case(self, case_id: str) -> str:
        """Migrate a flat (legacy) case to the multi-image layout.

        Moves ``evidence/``, ``parsed/``, and ``parsed_deduplicated/``
        from directly under the case directory into a new
        ``images/<image_id>/`` subdirectory.  The ``reports/`` directory
        is created if absent.

        Args:
            case_id: UUID of the case.

        Returns:
            The image UUID assigned to the migrated data.

        Raises:
            FileNotFoundError: If the case directory does not exist.
            ValueError: If the case is not a legacy case.
        """
        case_dir = self._require_case_dir(case_id)

        if not self.is_legacy_case(case_id):
            raise ValueError(
                f"Case {case_id} is not a legacy case (no evidence/ at root)."
            )

        image_id = str(uuid4())
        images_dir = case_dir / "images"
        images_dir.mkdir(exist_ok=True)
        image_dir = images_dir / image_id
        image_dir.mkdir(exist_ok=True)

        # Move each legacy subdirectory into the image slot.
        for subdir_name in ("evidence", "parsed", "parsed_deduplicated"):
            src = case_dir / subdir_name
            dst = image_dir / subdir_name
            if src.is_dir():
                shutil.move(str(src), str(dst))
                logger.info(
                    "Migrated %s -> %s", src, dst,
                )
            else:
                # Ensure the target directory exists even if the source
                # did not.
                dst.mkdir(exist_ok=True)

        # Write image metadata.
        metadata = {
            "label": "migrated",
            "image_id": image_id,
            "created": _utc_now_iso8601(),
        }
        (image_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8",
        )

        # Ensure reports/ exists at case level.
        (case_dir / "reports").mkdir(exist_ok=True)

        # Audit the migration.
        audit = AuditLogger(case_dir)
        audit.log("legacy_case_migrated", {
            "case_id": case_id,
            "image_id": image_id,
            "migrated_dirs": ["evidence", "parsed", "parsed_deduplicated"],
        })

        logger.info("Migrated legacy case %s to multi-image layout", case_id)
        return image_id

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_case_dir(self, case_id: str) -> Path:
        """Return the case directory path, raising if it does not exist.

        Args:
            case_id: UUID of the case.

        Returns:
            Resolved :class:`~pathlib.Path` to the case directory.

        Raises:
            FileNotFoundError: If the directory does not exist.
        """
        case_dir = self.cases_dir / case_id
        if not case_dir.is_dir():
            raise FileNotFoundError(f"Case directory not found: {case_dir}")
        return case_dir
