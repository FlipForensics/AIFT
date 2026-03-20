"""Tests for evidence format support.

Covers:
- Dissect container module importability (verifies format libraries are installed)
- Segment regex matching (EWF variants, split raw)
- Archive extraction functions (_extract_zip, _extract_tar, _extract_7z)
- Evidence path resolution (_resolve_uploaded_dissect_path)
- Evidence intake for various formats via the API
"""

from __future__ import annotations

import io
import json
import tarfile
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import py7zr

from app import create_app
import app.routes as routes
import app.routes.evidence as routes_evidence
import app.routes.handlers as routes_handlers
import app.routes.state as routes_state
import app.routes.tasks as routes_tasks


# ---------------------------------------------------------------------------
# Helpers reused from test_routes
# ---------------------------------------------------------------------------

class FakeParser:
    def __init__(
        self,
        evidence_path: str | Path,
        case_dir: str | Path,
        audit_logger: object,
        parsed_dir: str | Path | None = None,
    ) -> None:
        del evidence_path, audit_logger
        self.case_dir = Path(case_dir)
        self.parsed_dir = Path(parsed_dir) if parsed_dir is not None else self.case_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> "FakeParser":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def get_image_metadata(self) -> dict[str, str]:
        return {
            "hostname": "test-host",
            "os_version": "Windows 10",
            "domain": "test.local",
            "ips": "10.0.0.1",
            "timezone": "UTC",
            "install_date": "2025-06-01",
        }

    def get_available_artifacts(self) -> list[dict[str, object]]:
        return [{"key": "runkeys", "name": "Run/RunOnce Keys", "available": True}]


FAKE_HASHES = {"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4}


# ---------------------------------------------------------------------------
# 1. Dissect container module importability
# ---------------------------------------------------------------------------

class TestDissectModulesImportable(unittest.TestCase):
    """Verify that Dissect container/loader modules are importable.

    This doesn't need real evidence — it just confirms the installed dissect
    package includes support for each format we advertise.
    """

    def _try_import(self, module_path: str) -> None:
        try:
            __import__(module_path)
        except ImportError:
            self.skipTest(f"{module_path} not installed (optional Dissect plugin)")

    def test_ewf_container(self) -> None:
        self._try_import("dissect.evidence.ewf")

    def test_vmdk_container(self) -> None:
        self._try_import("dissect.hypervisor.descriptor.vmx")

    def test_vhd_container(self) -> None:
        self._try_import("dissect.hypervisor.disk.vhd")

    def test_qcow2_container(self) -> None:
        self._try_import("dissect.hypervisor.disk.qcow2")

    def test_vdi_container(self) -> None:
        self._try_import("dissect.hypervisor.disk.vdi")

    def test_target_open_exists(self) -> None:
        from dissect.target import Target
        self.assertTrue(callable(Target.open))

    def test_py7zr_importable(self) -> None:
        import py7zr  # noqa: F811
        self.assertTrue(hasattr(py7zr, "SevenZipFile"))


# ---------------------------------------------------------------------------
# 2. Segment regex matching
# ---------------------------------------------------------------------------

class TestSegmentRegexes(unittest.TestCase):
    """Test EWF_SEGMENT_RE and SPLIT_RAW_SEGMENT_RE patterns."""

    # -- EWF variants --

    def test_ewf_e01(self) -> None:
        m = routes_evidence.EWF_SEGMENT_RE.match("Disk.E01")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("base"), "Disk")
        self.assertEqual(m.group("segment"), "01")

    def test_ewf_e02_case_insensitive(self) -> None:
        m = routes_evidence.EWF_SEGMENT_RE.match("Image.e02")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("segment"), "02")

    def test_ewf_ex01(self) -> None:
        m = routes_evidence.EWF_SEGMENT_RE.match("Disk.Ex01")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("base"), "Disk")
        self.assertEqual(m.group("segment"), "01")

    def test_ewf_s01(self) -> None:
        m = routes_evidence.EWF_SEGMENT_RE.match("Evidence.S01")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("base"), "Evidence")

    def test_ewf_l01(self) -> None:
        m = routes_evidence.EWF_SEGMENT_RE.match("LogicalImage.L01")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("base"), "LogicalImage")

    def test_ewf_no_match_on_vmdk(self) -> None:
        m = routes_evidence.EWF_SEGMENT_RE.match("disk.vmdk")
        self.assertIsNone(m)

    # -- Split raw segments --

    def test_split_raw_000(self) -> None:
        m = routes_evidence.SPLIT_RAW_SEGMENT_RE.match("disk.000")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("base"), "disk")
        self.assertEqual(m.group("segment"), "000")

    def test_split_raw_001(self) -> None:
        m = routes_evidence.SPLIT_RAW_SEGMENT_RE.match("disk.001")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("segment"), "001")

    def test_split_raw_no_match_on_e01(self) -> None:
        # E01 only has 2-digit suffix, should not match 3-digit pattern
        m = routes_evidence.SPLIT_RAW_SEGMENT_RE.match("Disk.E01")
        self.assertIsNone(m)


# ---------------------------------------------------------------------------
# 3. Archive extraction functions
# ---------------------------------------------------------------------------

class TestExtractZip(unittest.TestCase):
    """Test _extract_zip with various content types inside the archive."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-zip-test-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_zip_containing_e01(self) -> None:
        zip_path = self.root / "evidence.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("case/Disk.E01", b"EWF-DATA")
            zf.writestr("case/Disk.E02", b"EWF-DATA-2")
        result = routes_evidence._extract_zip(zip_path, dest)
        self.assertTrue(str(result).endswith(".E01"))

    def test_zip_containing_vmdk(self) -> None:
        zip_path = self.root / "vm.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("server.vmdk", b"VMDK-DATA")
        result = routes_evidence._extract_zip(zip_path, dest)
        self.assertTrue(str(result).endswith(".vmdk"))

    def test_zip_containing_dd(self) -> None:
        zip_path = self.root / "raw.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("disk.dd", b"RAW-DATA")
        result = routes_evidence._extract_zip(zip_path, dest)
        self.assertTrue(str(result).endswith(".dd"))

    def test_zip_containing_vhd(self) -> None:
        zip_path = self.root / "hyperv.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("machine.vhdx", b"VHDX-DATA")
        result = routes_evidence._extract_zip(zip_path, dest)
        self.assertTrue(str(result).endswith(".vhdx"))

    def test_zip_prefers_e01_over_other_formats(self) -> None:
        zip_path = self.root / "mixed.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("disk.vmdk", b"VMDK-DATA")
            zf.writestr("disk.E01", b"EWF-DATA")
        result = routes_evidence._extract_zip(zip_path, dest)
        self.assertTrue(str(result).endswith(".E01"))

    def test_zip_triage_collection_returns_directory(self) -> None:
        zip_path = self.root / "triage.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("Windows/System32/config/SAM", b"sam")
            zf.writestr("Users/Admin/NTUSER.DAT", b"reg")
        result = routes_evidence._extract_zip(zip_path, dest)
        self.assertTrue(result.is_dir())

    def test_zip_empty_raises(self) -> None:
        zip_path = self.root / "empty.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            pass  # empty archive
        with self.assertRaises(ValueError, msg="Evidence ZIP is empty."):
            routes_evidence._extract_zip(zip_path, dest)

    def test_zip_path_traversal_raises(self) -> None:
        zip_path = self.root / "evil.zip"
        dest = self.root / "extracted"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("../../etc/passwd", b"root:x:0:0")
        with self.assertRaises(ValueError, msg="unsafe paths"):
            routes_evidence._extract_zip(zip_path, dest)


class TestExtractTar(unittest.TestCase):
    """Test _extract_tar with various content types."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-tar-test-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _make_tar(self, name: str, files: dict[str, bytes], compress: bool = False) -> Path:
        tar_path = self.root / name
        mode = "w:gz" if compress else "w"
        with tarfile.open(tar_path, mode) as tf:
            for fname, data in files.items():
                info = tarfile.TarInfo(name=fname)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return tar_path

    def test_tar_containing_e01(self) -> None:
        tar_path = self._make_tar("evidence.tar", {"Disk.E01": b"EWF", "Disk.E02": b"EWF2"})
        dest = self.root / "extracted"
        result = routes_evidence._extract_tar(tar_path, dest)
        self.assertTrue(str(result).endswith(".E01"))

    def test_tar_gz_containing_vmdk(self) -> None:
        tar_path = self._make_tar("vm.tar.gz", {"server.vmdk": b"VMDK"}, compress=True)
        dest = self.root / "extracted"
        result = routes_evidence._extract_tar(tar_path, dest)
        self.assertTrue(str(result).endswith(".vmdk"))

    def test_tar_containing_raw_image(self) -> None:
        tar_path = self._make_tar("raw.tar", {"disk.raw": b"RAW"})
        dest = self.root / "extracted"
        result = routes_evidence._extract_tar(tar_path, dest)
        self.assertTrue(str(result).endswith(".raw"))

    def test_tar_triage_returns_directory(self) -> None:
        tar_path = self._make_tar("triage.tar", {
            "Windows/System32/config/SAM": b"sam",
            "Users/Admin/NTUSER.DAT": b"reg",
        })
        dest = self.root / "extracted"
        result = routes_evidence._extract_tar(tar_path, dest)
        self.assertTrue(result.is_dir())

    def test_tar_path_traversal_raises(self) -> None:
        tar_path = self._make_tar("evil.tar", {"../../etc/passwd": b"root"})
        dest = self.root / "extracted"
        with self.assertRaises(ValueError, msg="unsafe paths"):
            routes_evidence._extract_tar(tar_path, dest)


class TestExtract7z(unittest.TestCase):
    """Test _extract_7z with various content types."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-7z-test-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _make_7z(self, name: str, files: dict[str, bytes]) -> Path:
        archive_path = self.root / name
        with py7zr.SevenZipFile(archive_path, mode="w") as szf:
            for fname, data in files.items():
                szf.writestr(data, fname)
        return archive_path

    def test_7z_containing_e01(self) -> None:
        archive_path = self._make_7z("evidence.7z", {"Disk.E01": b"EWF", "Disk.E02": b"EWF2"})
        dest = self.root / "extracted"
        result = routes_evidence._extract_7z(archive_path, dest)
        self.assertTrue(str(result).endswith(".E01"))

    def test_7z_containing_vmdk(self) -> None:
        archive_path = self._make_7z("vm.7z", {"server.vmdk": b"VMDK-DATA"})
        dest = self.root / "extracted"
        result = routes_evidence._extract_7z(archive_path, dest)
        self.assertTrue(str(result).endswith(".vmdk"))

    def test_7z_containing_dd(self) -> None:
        archive_path = self._make_7z("raw.7z", {"disk.dd": b"RAW-DATA"})
        dest = self.root / "extracted"
        result = routes_evidence._extract_7z(archive_path, dest)
        self.assertTrue(str(result).endswith(".dd"))

    def test_7z_triage_returns_directory(self) -> None:
        archive_path = self._make_7z("triage.7z", {
            "Windows/System32/config/SAM": b"sam",
            "Users/Admin/NTUSER.DAT": b"reg",
        })
        dest = self.root / "extracted"
        result = routes_evidence._extract_7z(archive_path, dest)
        self.assertTrue(result.is_dir())

    def test_7z_prefers_e01(self) -> None:
        archive_path = self._make_7z("mixed.7z", {
            "disk.vmdk": b"VMDK",
            "disk.E01": b"EWF",
        })
        dest = self.root / "extracted"
        result = routes_evidence._extract_7z(archive_path, dest)
        self.assertTrue(str(result).endswith(".E01"))


# ---------------------------------------------------------------------------
# 4. Evidence path resolution (_resolve_uploaded_dissect_path)
# ---------------------------------------------------------------------------

class TestResolveUploadedDissectPath(unittest.TestCase):
    """Test segment grouping and archive rejection logic."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-resolve-test-")
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _touch(self, name: str) -> Path:
        p = self.root / name
        p.write_bytes(b"test")
        return p

    def test_single_file_returned_directly(self) -> None:
        p = self._touch("disk.vmdk")
        result = routes_evidence._resolve_uploaded_dissect_path([p])
        self.assertEqual(result, p)

    def test_ewf_segments_returns_e01(self) -> None:
        paths = [self._touch(f"Disk.E0{i}") for i in range(1, 5)]
        result = routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertTrue(result.name.endswith(".E01"))

    def test_ex01_segments_returns_first(self) -> None:
        paths = [self._touch("Disk.Ex01"), self._touch("Disk.Ex02")]
        result = routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertTrue(result.name.endswith(".Ex01"))

    def test_s01_segments_returns_first(self) -> None:
        paths = [self._touch("Disk.S01"), self._touch("Disk.S02")]
        result = routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertTrue(result.name.endswith(".S01"))

    def test_l01_segments_returns_first(self) -> None:
        paths = [self._touch("Image.L01"), self._touch("Image.L02")]
        result = routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertTrue(result.name.endswith(".L01"))

    def test_split_raw_segments_returns_000(self) -> None:
        paths = [self._touch("disk.001"), self._touch("disk.000"), self._touch("disk.002")]
        result = routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertTrue(result.name.endswith(".000"))

    def test_zip_mixed_with_others_raises(self) -> None:
        paths = [self._touch("archive.zip"), self._touch("Disk.E01")]
        with self.assertRaises(ValueError, msg="archive"):
            routes_evidence._resolve_uploaded_dissect_path(paths)

    def test_7z_mixed_with_others_raises(self) -> None:
        paths = [self._touch("archive.7z"), self._touch("disk.vmdk")]
        with self.assertRaises(ValueError, msg="archive"):
            routes_evidence._resolve_uploaded_dissect_path(paths)

    def test_tar_mixed_with_others_raises(self) -> None:
        paths = [self._touch("evidence.tar"), self._touch("disk.dd")]
        with self.assertRaises(ValueError, msg="archive"):
            routes_evidence._resolve_uploaded_dissect_path(paths)

    def test_multiple_segment_groups_raises(self) -> None:
        paths = [
            self._touch("DiskA.E01"),
            self._touch("DiskA.E02"),
            self._touch("DiskB.E01"),
            self._touch("DiskB.E02"),
        ]
        with self.assertRaises(ValueError, msg="Ambiguous upload"):
            routes_evidence._resolve_uploaded_dissect_path(paths)

    def test_multiple_segment_groups_error_lists_names(self) -> None:
        paths = [
            self._touch("Alpha.E01"),
            self._touch("Beta.E01"),
        ]
        with self.assertRaises(ValueError) as ctx:
            routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertIn("alpha", str(ctx.exception))
        self.assertIn("beta", str(ctx.exception))

    def test_single_segment_group_still_succeeds(self) -> None:
        paths = [
            self._touch("Disk.E01"),
            self._touch("Disk.E02"),
            self._touch("Disk.E03"),
        ]
        result = routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertTrue(result.name.endswith(".E01"))

    def test_two_standalone_images_raises(self) -> None:
        """Reject two unrelated standalone evidence files (no segment pattern)."""
        paths = [self._touch("disk1.vmdk"), self._touch("disk2.vmdk")]
        with self.assertRaises(ValueError) as ctx:
            routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertIn("Ambiguous upload", str(ctx.exception))

    def test_two_different_format_standalone_raises(self) -> None:
        """Reject mixed standalone formats (e.g. .dd and .vmdk)."""
        paths = [self._touch("image.dd"), self._touch("backup.vmdk")]
        with self.assertRaises(ValueError) as ctx:
            routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertIn("Ambiguous upload", str(ctx.exception))

    def test_three_standalone_images_raises(self) -> None:
        """Reject three unrelated standalone evidence files."""
        paths = [self._touch("a.raw"), self._touch("b.img"), self._touch("c.dd")]
        with self.assertRaises(ValueError) as ctx:
            routes_evidence._resolve_uploaded_dissect_path(paths)
        self.assertIn("single evidence file", str(ctx.exception))

    def test_empty_list_raises(self) -> None:
        with self.assertRaises(ValueError):
            routes_evidence._resolve_uploaded_dissect_path([])


# ---------------------------------------------------------------------------
# 5. Evidence intake API tests for various formats
# ---------------------------------------------------------------------------

class TestEvidenceIntakeFormats(unittest.TestCase):
    """Test the /api/cases/<id>/evidence endpoint with different file types."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-intake-test-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.app.config["CSRF_TOKEN"]
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_case(self) -> str:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
        ):
            resp = self.client.post("/api/cases", json={"case_name": "Format Test"})
            self.assertEqual(resp.status_code, 201)
            return resp.get_json()["case_id"]

    def _intake_path(self, case_id: str, evidence_path: Path) -> dict:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_handlers, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
            return resp.get_json()

    def test_intake_vmdk(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "server.vmdk"
        evidence.write_bytes(b"VMDK")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("server.vmdk", payload["source_path"])

    def test_intake_vhd(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "machine.vhd"
        evidence.write_bytes(b"VHD")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("machine.vhd", payload["source_path"])

    def test_intake_vhdx(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "machine.vhdx"
        evidence.write_bytes(b"VHDX")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("machine.vhdx", payload["source_path"])

    def test_intake_qcow2(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "disk.qcow2"
        evidence.write_bytes(b"QCOW2")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("disk.qcow2", payload["source_path"])

    def test_intake_vdi(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "disk.vdi"
        evidence.write_bytes(b"VDI")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("disk.vdi", payload["source_path"])

    def test_intake_dd(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "disk.dd"
        evidence.write_bytes(b"RAW")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("disk.dd", payload["source_path"])

    def test_intake_raw(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "disk.raw"
        evidence.write_bytes(b"RAW")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("disk.raw", payload["source_path"])

    def test_intake_img(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "disk.img"
        evidence.write_bytes(b"RAW")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("disk.img", payload["source_path"])

    def test_intake_ad1(self) -> None:
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "logical.ad1"
        evidence.write_bytes(b"AD1")
        payload = self._intake_path(case_id, evidence)
        self.assertIn("logical.ad1", payload["source_path"])

    def test_intake_7z_extracts_and_finds_evidence(self) -> None:
        case_id = self._create_case()
        archive_path = Path(self.temp_dir.name) / "evidence.7z"
        with py7zr.SevenZipFile(archive_path, mode="w") as szf:
            szf.writestr(b"EWF-DATA", "Disk.E01")
            szf.writestr(b"EWF-DATA-2", "Disk.E02")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_handlers, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(archive_path)},
            )
            self.assertEqual(resp.status_code, 200)
            payload = resp.get_json()
            self.assertTrue(payload["evidence_path"].endswith(".E01"))

    def test_intake_tar_extracts_and_finds_evidence(self) -> None:
        case_id = self._create_case()
        tar_path = Path(self.temp_dir.name) / "evidence.tar"
        with tarfile.open(tar_path, "w") as tf:
            data = b"VMDK-DATA"
            info = tarfile.TarInfo(name="server.vmdk")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_handlers, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(tar_path)},
            )
            self.assertEqual(resp.status_code, 200)
            payload = resp.get_json()
            self.assertTrue(payload["evidence_path"].endswith(".vmdk"))

    def test_intake_directory_path(self) -> None:
        case_id = self._create_case()
        evidence_dir = Path(self.temp_dir.name) / "kape_output"
        evidence_dir.mkdir()
        (evidence_dir / "SAM").write_bytes(b"sam")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_handlers, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_dir)},
            )
            self.assertEqual(resp.status_code, 200)
            payload = resp.get_json()
            self.assertEqual(payload["hashes"]["sha256"], "N/A (directory)")

    def test_intake_upload_split_s01_segments(self) -> None:
        case_id = self._create_case()
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_handlers, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": [
                        (BytesIO(b"seg1"), "Disk.S01"),
                        (BytesIO(b"seg2"), "Disk.S02"),
                    ]
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(resp.status_code, 200)
            payload = resp.get_json()
            self.assertTrue(payload["evidence_path"].endswith(".S01"))

    def test_intake_upload_split_raw_segments(self) -> None:
        case_id = self._create_case()
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_handlers, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": [
                        (BytesIO(b"seg0"), "disk.000"),
                        (BytesIO(b"seg1"), "disk.001"),
                        (BytesIO(b"seg2"), "disk.002"),
                    ]
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(resp.status_code, 200)
            payload = resp.get_json()
            self.assertTrue(payload["evidence_path"].endswith(".000"))


# ---------------------------------------------------------------------------
# 6. Extension constants consistency
# ---------------------------------------------------------------------------

class TestExtensionConstants(unittest.TestCase):
    """Verify that the extension sets are consistent."""

    def test_evidence_file_extensions_subset_of_dissect_extensions(self) -> None:
        """Every extension we search for inside archives should also be in the
        main DISSECT_EVIDENCE_EXTENSIONS set."""
        missing = routes_evidence._EVIDENCE_FILE_EXTENSIONS - routes_state.DISSECT_EVIDENCE_EXTENSIONS
        self.assertFalse(
            missing,
            f"_EVIDENCE_FILE_EXTENSIONS has entries not in DISSECT_EVIDENCE_EXTENSIONS: {missing}",
        )


# ---------------------------------------------------------------------------
# 7. Evidence integrity regression tests
# ---------------------------------------------------------------------------

class TestEvidenceIntegrityArchive(unittest.TestCase):
    """Verify that archive intake hashes the archive file and report
    verification uses the stored evidence_file_hashes."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-integrity-archive-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.app.config["CSRF_TOKEN"]
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_case(self) -> str:
        """Create a fresh case and return its ID."""
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
        ):
            resp = self.client.post("/api/cases", json={"case_name": "Archive Integrity"})
            self.assertEqual(resp.status_code, 201)
            return resp.get_json()["case_id"]

    def test_archive_intake_stores_file_hashes_for_source(self) -> None:
        """Intake of a ZIP must record evidence_file_hashes for the ZIP itself."""
        case_id = self._create_case()
        zip_path = Path(self.temp_dir.name) / "evidence.zip"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("Disk.E01", b"EWF-DATA")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(zip_path)},
            )
            self.assertEqual(resp.status_code, 200)

        with routes.STATE_LOCK:
            case = routes.CASE_STATES[case_id]
            file_hashes = case.get("evidence_file_hashes", [])

        self.assertEqual(len(file_hashes), 1)
        self.assertEqual(file_hashes[0]["path"], str(zip_path))
        self.assertEqual(file_hashes[0]["sha256"], "a" * 64)

    def test_archive_report_verifies_via_evidence_file_hashes(self) -> None:
        """Report generation for archived evidence must verify using the stored
        evidence_file_hashes, calling verify_hash for each entry."""
        case_id = self._create_case()
        zip_path = Path(self.temp_dir.name) / "evidence.zip"
        with ZipFile(zip_path, "w") as zf:
            zf.writestr("Disk.E01", b"EWF-DATA")

        from app.reporter import ReportGenerator as _RealRG

        class _FakeRG(_RealRG):
            def generate(self, **kwargs):
                report_dir = self.cases_root / case_id / "reports"
                report_dir.mkdir(parents=True, exist_ok=True)
                report_path = report_dir / "report.html"
                report_path.write_text("<html>ok</html>", encoding="utf-8")
                return report_path

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "ReportGenerator", _FakeRG),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)) as mock_verify,
        ):
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(zip_path)})
            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)
            mock_verify.assert_called_once()
            called_path = mock_verify.call_args.args[0]
            self.assertEqual(str(called_path), str(zip_path))


class TestEvidenceIntegritySplitSegments(unittest.TestCase):
    """Verify that split-image uploads hash and verify ALL segments."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-integrity-split-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.app.config["CSRF_TOKEN"]
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_case(self) -> str:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
        ):
            resp = self.client.post("/api/cases", json={"case_name": "Split Integrity"})
            self.assertEqual(resp.status_code, 201)
            return resp.get_json()["case_id"]

    def test_split_upload_hashes_all_segments(self) -> None:
        """Uploading E01+E02 must produce evidence_file_hashes for both."""
        case_id = self._create_case()
        call_count = {"n": 0}

        def _fake_compute(filepath, progress_callback=None):
            call_count["n"] += 1
            return {"sha256": f"{call_count['n']:0>64x}", "md5": f"{call_count['n']:0>32x}", "size_bytes": 4}

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "compute_hashes", side_effect=_fake_compute),
        ):
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": [
                        (io.BytesIO(b"seg1"), "Disk.E01"),
                        (io.BytesIO(b"seg2"), "Disk.E02"),
                    ]
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(resp.status_code, 200)

        # compute_hashes must have been called for both segments.
        self.assertEqual(call_count["n"], 2)

        with routes.STATE_LOCK:
            file_hashes = routes.CASE_STATES[case_id].get("evidence_file_hashes", [])
        self.assertEqual(len(file_hashes), 2)

    def test_split_report_verifies_all_segments(self) -> None:
        """Report generation must verify every segment, not just the primary."""
        case_id = self._create_case()

        from app.reporter import ReportGenerator as _RealRG

        class _FakeRG(_RealRG):
            def generate(self, **kwargs):
                report_dir = self.cases_root / case_id / "reports"
                report_dir.mkdir(parents=True, exist_ok=True)
                rp = report_dir / "report.html"
                rp.write_text("<html>ok</html>", encoding="utf-8")
                return rp

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "ReportGenerator", _FakeRG),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)) as mock_verify,
        ):
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": [
                        (io.BytesIO(b"seg1"), "Disk.E01"),
                        (io.BytesIO(b"seg2"), "Disk.E02"),
                    ]
                },
                content_type="multipart/form-data",
            )
            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)
            # verify_hash must be called once per segment.
            self.assertEqual(mock_verify.call_count, 2)


class TestEvidenceIntegrityTamperDetection(unittest.TestCase):
    """Verify that tampered evidence is detected at report time."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-integrity-tamper-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.app.config["CSRF_TOKEN"]
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_case(self) -> str:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
        ):
            resp = self.client.post("/api/cases", json={"case_name": "Tamper Test"})
            self.assertEqual(resp.status_code, 201)
            return resp.get_json()["case_id"]

    def test_tampered_evidence_fails_verification(self) -> None:
        """If evidence changes after intake, report verification must fail."""
        case_id = self._create_case()
        evidence = Path(self.temp_dir.name) / "disk.E01"
        evidence.write_bytes(b"original-data")

        from app.reporter import ReportGenerator as _RealRG

        class _FakeRG(_RealRG):
            def generate(self, **kwargs):
                report_dir = self.cases_root / case_id / "reports"
                report_dir.mkdir(parents=True, exist_ok=True)
                rp = report_dir / "report.html"
                rp.write_text("<html>ok</html>", encoding="utf-8")
                return rp

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "compute_hashes", return_value=FAKE_HASHES),
            patch.object(routes_evidence, "ReportGenerator", _FakeRG),
            # Simulate tamper: verify_hash returns mismatch.
            patch.object(routes_evidence, "verify_hash", return_value=(False, "c" * 64)),
        ):
            self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence)},
            )
            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            # Report still generates (with FAIL status), not a hard error.
            self.assertEqual(report_resp.status_code, 200)

            # Audit log must record the failure.
            audit_path = self.cases_root / case_id / "audit.jsonl"
            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            hash_events = [e for e in entries if e.get("action") == "hash_verification"]
            self.assertTrue(hash_events)
            self.assertFalse(hash_events[-1]["details"]["match"])


if __name__ == "__main__":
    unittest.main()
