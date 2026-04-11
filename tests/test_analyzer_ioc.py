"""Tests for analyzer IOC extraction and formatting helpers.

Covers standalone function tests from app.analyzer.ioc including
tool keyword extraction, IOC target extraction, false positive helpers,
formatting, and priority directives.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.analyzer import ForensicAnalyzer

###############################################################################
# ioc.py — standalone function tests
###############################################################################


class TestExtractToolKeywords(unittest.TestCase):
    """Tests for ioc.extract_tool_keywords."""

    def test_finds_keywords(self) -> None:
        from app.analyzer.ioc import extract_tool_keywords
        result = extract_tool_keywords("Used mimikatz and psexec for lateral movement.")
        self.assertIn("mimikatz", result)
        self.assertIn("psexec", result)

    def test_case_insensitive(self) -> None:
        from app.analyzer.ioc import extract_tool_keywords
        result = extract_tool_keywords("MIMIKATZ was found")
        self.assertIn("mimikatz", result)

    def test_no_matches(self) -> None:
        from app.analyzer.ioc import extract_tool_keywords
        result = extract_tool_keywords("Normal application behavior")
        self.assertEqual(result, [])


class TestExtractIocTargetsStandalone(unittest.TestCase):
    """Tests for ioc.extract_ioc_targets."""

    def test_empty_context(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        self.assertEqual(extract_ioc_targets(""), {})

    def test_extracts_urls(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("Check https://evil.com/payload")
        self.assertIn("URLs", result)
        self.assertIn("https://evil.com/payload", result["URLs"])

    def test_extracts_ips(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("IP 192.168.1.100 was seen.")
        self.assertIn("IPv4", result)
        self.assertIn("192.168.1.100", result["IPv4"])

    def test_extracts_hashes(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract_ioc_targets(f"Hash: {md5}")
        self.assertIn("Hashes", result)
        self.assertIn(md5, result["Hashes"])

    def test_extracts_emails(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("Contact attacker@evil.com")
        self.assertIn("Emails", result)

    def test_extracts_filenames(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("Found malware.exe on disk")
        self.assertIn("FileNames", result)

    def test_excludes_local_domains(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("Host dc01.corp.local was queried.")
        domains = result.get("Domains", [])
        local_domains = [d for d in domains if d.endswith(".local")]
        self.assertEqual(len(local_domains), 0)

    def test_url_hosts_not_duplicated_as_domains(self) -> None:
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("Visit https://evil.example.com/path for details.")
        domains = result.get("Domains", [])
        self.assertNotIn("evil.example.com", [d.lower() for d in domains])

    def test_excludes_file_extension_domains(self) -> None:
        """Strings like 'file.exe', 'System.dll', 'config.xml' are not domains."""
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets(
            "Found System.dll and config.xml and data.json in the directory."
        )
        domains = result.get("Domains", [])
        for fp in ["System.dll", "config.xml", "data.json"]:
            self.assertNotIn(fp, domains)

    def test_excludes_version_strings_as_domains(self) -> None:
        """Version strings like 'v2.0', '1.2.3' are not domains."""
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("Running version v2.0 and build 1.2.3.")
        domains = result.get("Domains", [])
        for v in ["v2.0", "1.2.3"]:
            self.assertNotIn(v, domains)

    def test_excludes_guid_hashes(self) -> None:
        """GUID hex strings from hyphenated GUIDs should not be extracted as hashes."""
        from app.analyzer.ioc import extract_ioc_targets
        guid = "550e8400-e29b-41d4-a716-446655440000"
        result = extract_ioc_targets(f"Session GUID: {guid}")
        hashes = result.get("Hashes", [])
        guid_hex = guid.replace("-", "")
        self.assertNotIn(guid_hex, hashes)

    def test_excludes_all_zero_hashes(self) -> None:
        """All-zero hex strings are placeholders, not IOC hashes."""
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets(f"Hash: {'0' * 32}")
        hashes = result.get("Hashes", [])
        self.assertNotIn("0" * 32, hashes)

    def test_keeps_real_md5_hash(self) -> None:
        """Real MD5 hashes should still be extracted."""
        from app.analyzer.ioc import extract_ioc_targets
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        result = extract_ioc_targets(f"Malware hash: {md5}")
        self.assertIn("Hashes", result)
        self.assertIn(md5, result["Hashes"])

    def test_keeps_real_domain(self) -> None:
        """Real domains like evil.com should still be extracted."""
        from app.analyzer.ioc import extract_ioc_targets
        result = extract_ioc_targets("C2 server at evil.com was contacted.")
        self.assertIn("Domains", result)
        self.assertIn("evil.com", result["Domains"])


class TestIocFalsePositiveHelpers(unittest.TestCase):
    """Tests for is_likely_false_positive_hash and is_likely_false_positive_domain."""

    def test_false_positive_hash_all_zeros(self) -> None:
        from app.analyzer.ioc import is_likely_false_positive_hash
        self.assertTrue(is_likely_false_positive_hash("0" * 32))
        self.assertTrue(is_likely_false_positive_hash("f" * 64))

    def test_false_positive_hash_guid(self) -> None:
        from app.analyzer.ioc import is_likely_false_positive_hash
        guid_hex = "550e8400e29b41d4a716446655440000"
        guid_set = {guid_hex}
        self.assertTrue(is_likely_false_positive_hash(guid_hex, guid_set))

    def test_real_hash_not_false_positive(self) -> None:
        from app.analyzer.ioc import is_likely_false_positive_hash
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        self.assertFalse(is_likely_false_positive_hash(md5))

    def test_false_positive_domain_exe(self) -> None:
        from app.analyzer.ioc import is_likely_false_positive_domain
        self.assertTrue(is_likely_false_positive_domain("svchost.exe"))
        self.assertTrue(is_likely_false_positive_domain("System.dll"))
        self.assertTrue(is_likely_false_positive_domain("config.xml"))

    def test_false_positive_domain_version(self) -> None:
        from app.analyzer.ioc import is_likely_false_positive_domain
        self.assertTrue(is_likely_false_positive_domain("v2.0"))
        self.assertTrue(is_likely_false_positive_domain("1.2.3"))

    def test_real_domain_not_false_positive(self) -> None:
        from app.analyzer.ioc import is_likely_false_positive_domain
        self.assertFalse(is_likely_false_positive_domain("evil.com"))
        self.assertFalse(is_likely_false_positive_domain("malware.example.org"))


class TestFormatIocTargets(unittest.TestCase):
    """Tests for ioc.format_ioc_targets."""

    def test_no_iocs(self) -> None:
        from app.analyzer.ioc import format_ioc_targets
        result = format_ioc_targets("Nothing special here.")
        self.assertIn("No explicit IOC", result)

    def test_formats_categories(self) -> None:
        from app.analyzer.ioc import format_ioc_targets
        result = format_ioc_targets("Check 192.168.1.1 and mimikatz")
        self.assertIn("- IPv4:", result)
        self.assertIn("192.168.1.1", result)


class TestBuildPriorityDirectives(unittest.TestCase):
    """Tests for ioc.build_priority_directives."""

    def test_with_iocs(self) -> None:
        from app.analyzer.ioc import build_priority_directives
        result = build_priority_directives("Check 192.168.1.1")
        self.assertIn("1.", result)
        self.assertIn("IOC", result)
        self.assertIn("Observed", result)

    def test_without_iocs(self) -> None:
        from app.analyzer.ioc import build_priority_directives
        result = build_priority_directives("Just general investigation.")
        self.assertIn("No explicit IOC", result)


class TestBuildArtifactFinalContextReminder(unittest.TestCase):
    """Tests for ioc.build_artifact_final_context_reminder."""

    def test_basic_structure(self) -> None:
        from app.analyzer.ioc import build_artifact_final_context_reminder
        result = build_artifact_final_context_reminder(
            artifact_key="runkeys",
            artifact_name="Run/RunOnce Keys",
            investigation_context="Check for persistence.",
        )
        self.assertIn("## Final Context Reminder", result)
        self.assertIn("runkeys", result)
        self.assertIn("Run/RunOnce Keys", result)
        self.assertIn("Check for persistence", result)

    def test_empty_context(self) -> None:
        from app.analyzer.ioc import build_artifact_final_context_reminder
        result = build_artifact_final_context_reminder(
            artifact_key="k", artifact_name="n", investigation_context="",
        )
        self.assertIn("No investigation context provided", result)


###############################################################################
# prompts.py — standalone function tests
###############################################################################


class TestLoadPromptTemplate(unittest.TestCase):
    """Tests for prompts.load_prompt_template."""

    def test_reads_file(self) -> None:
        from app.analyzer.prompts import load_prompt_template
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            (p / "test.md").write_text("TEMPLATE CONTENT", encoding="utf-8")
            result = load_prompt_template(p, "test.md", "fallback")
        self.assertEqual(result, "TEMPLATE CONTENT")

    def test_fallback_on_missing_file(self) -> None:
        from app.analyzer.prompts import load_prompt_template
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            result = load_prompt_template(Path(tmp_dir), "nonexistent.md", "fallback")
        self.assertEqual(result, "fallback")


class TestLoadArtifactInstructionPrompts(unittest.TestCase):
    """Tests for prompts.load_artifact_instruction_prompts."""

    def test_loads_md_files(self) -> None:
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            inst_dir = p / "artifact_instructions"
            inst_dir.mkdir()
            (inst_dir / "evtx.md").write_text("EVTX INSTRUCTIONS", encoding="utf-8")
            (inst_dir / "mft.md").write_text("MFT INSTRUCTIONS", encoding="utf-8")
            result = load_artifact_instruction_prompts(p)
        self.assertEqual(result["evtx"], "EVTX INSTRUCTIONS")
        self.assertEqual(result["mft"], "MFT INSTRUCTIONS")

    def test_missing_dir_returns_empty(self) -> None:
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            result = load_artifact_instruction_prompts(Path(tmp_dir))
        self.assertEqual(result, {})

    def test_empty_files_skipped(self) -> None:
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            inst_dir = p / "artifact_instructions"
            inst_dir.mkdir()
            (inst_dir / "empty.md").write_text("", encoding="utf-8")
            (inst_dir / "valid.md").write_text("Content", encoding="utf-8")
            result = load_artifact_instruction_prompts(p)
        self.assertNotIn("empty", result)
        self.assertIn("valid", result)

    def test_linux_os_type_loads_linux_instructions(self) -> None:
        """When os_type='linux', the function reads from artifact_instructions_linux/."""
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            linux_dir = p / "artifact_instructions_linux"
            linux_dir.mkdir()
            (linux_dir / "bash_history.md").write_text("BASH INSTRUCTIONS", encoding="utf-8")
            (linux_dir / "syslog.md").write_text("SYSLOG INSTRUCTIONS", encoding="utf-8")
            result = load_artifact_instruction_prompts(p, os_type="linux")
        self.assertEqual(result["bash_history"], "BASH INSTRUCTIONS")
        self.assertEqual(result["syslog"], "SYSLOG INSTRUCTIONS")

    def test_windows_os_type_loads_windows_instructions(self) -> None:
        """When os_type='windows', the function reads from artifact_instructions/."""
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            win_dir = p / "artifact_instructions"
            win_dir.mkdir()
            (win_dir / "evtx.md").write_text("EVTX WIN", encoding="utf-8")
            linux_dir = p / "artifact_instructions_linux"
            linux_dir.mkdir()
            (linux_dir / "bash_history.md").write_text("BASH LINUX", encoding="utf-8")
            result = load_artifact_instruction_prompts(p, os_type="windows")
        self.assertIn("evtx", result)
        self.assertNotIn("bash_history", result)

    def test_default_os_type_is_windows(self) -> None:
        """Without os_type the function defaults to the Windows directory."""
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            win_dir = p / "artifact_instructions"
            win_dir.mkdir()
            (win_dir / "mft.md").write_text("MFT DATA", encoding="utf-8")
            result = load_artifact_instruction_prompts(p)
        self.assertIn("mft", result)

    def test_unknown_os_type_falls_back_to_windows(self) -> None:
        """An unrecognised OS type should fall back to Windows instructions."""
        from app.analyzer.prompts import load_artifact_instruction_prompts
        with TemporaryDirectory(prefix="aift-prompt-") as tmp_dir:
            p = Path(tmp_dir)
            win_dir = p / "artifact_instructions"
            win_dir.mkdir()
            (win_dir / "prefetch.md").write_text("PREFETCH DATA", encoding="utf-8")
            result = load_artifact_instruction_prompts(p, os_type="esxi")
        self.assertIn("prefetch", result)


class TestResolveArtifactAiColumnsConfigPath(unittest.TestCase):
    """Tests for prompts.resolve_artifact_ai_columns_config_path."""

    def test_absolute_path_returned_as_is(self) -> None:
        from app.analyzer.prompts import resolve_artifact_ai_columns_config_path
        with TemporaryDirectory(prefix="aift-abs-") as tmp_dir:
            abs_path = Path(tmp_dir) / "path.yaml"
            result = resolve_artifact_ai_columns_config_path(str(abs_path), None)
            self.assertEqual(result, abs_path)

    def test_relative_path_resolves_to_project_root(self) -> None:
        from app.analyzer.prompts import resolve_artifact_ai_columns_config_path
        from app.analyzer.constants import PROJECT_ROOT
        result = resolve_artifact_ai_columns_config_path("config/artifact_ai_columns.yaml", None)
        self.assertTrue(str(result).startswith(str(PROJECT_ROOT)))


class TestLoadArtifactAiColumnProjections(unittest.TestCase):
    """Tests for prompts.load_artifact_ai_column_projections."""

    def test_valid_yaml(self) -> None:
        from app.analyzer.prompts import load_artifact_ai_column_projections
        with TemporaryDirectory(prefix="aift-proj-") as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(
                "artifact_ai_columns:\n  runkeys:\n    - ts\n    - name\n",
                encoding="utf-8",
            )
            result = load_artifact_ai_column_projections(config_path)
        self.assertIn("runkeys", result)
        self.assertEqual(result["runkeys"], ("ts", "name"))

    def test_missing_file_returns_empty(self) -> None:
        from app.analyzer.prompts import load_artifact_ai_column_projections
        result = load_artifact_ai_column_projections(Path("/nonexistent.yaml"))
        self.assertEqual(result, {})

    def test_invalid_yaml_returns_empty(self) -> None:
        from app.analyzer.prompts import load_artifact_ai_column_projections
        with TemporaryDirectory(prefix="aift-proj-") as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text("[invalid yaml", encoding="utf-8")
            result = load_artifact_ai_column_projections(config_path)
        self.assertEqual(result, {})

    def test_non_mapping_returns_empty(self) -> None:
        from app.analyzer.prompts import load_artifact_ai_column_projections
        with TemporaryDirectory(prefix="aift-proj-") as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text("- just a list\n- item2\n", encoding="utf-8")
            result = load_artifact_ai_column_projections(config_path)
        self.assertEqual(result, {})


    def test_os_suffixed_key_used_for_matching_os(self) -> None:
        """services_linux columns should be used when os_type='linux'."""
        from app.analyzer.prompts import load_artifact_ai_column_projections
        with TemporaryDirectory(prefix="aift-proj-") as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(
                "artifact_ai_columns:\n"
                "  services:\n    - ts\n    - servicedll\n"
                "  services_linux:\n    - ts\n    - type\n    - source\n",
                encoding="utf-8",
            )
            result = load_artifact_ai_column_projections(config_path, os_type="linux")
        # services_linux should override services for Linux
        self.assertIn("services", result)
        self.assertIn("source", result["services"])
        self.assertNotIn("servicedll", result["services"])

    def test_os_suffixed_key_skipped_for_other_os(self) -> None:
        """services_linux columns should NOT be used when os_type='windows'."""
        from app.analyzer.prompts import load_artifact_ai_column_projections
        with TemporaryDirectory(prefix="aift-proj-") as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(
                "artifact_ai_columns:\n"
                "  services:\n    - ts\n    - servicedll\n"
                "  services_linux:\n    - ts\n    - type\n    - source\n",
                encoding="utf-8",
            )
            result = load_artifact_ai_column_projections(config_path, os_type="windows")
        self.assertIn("services", result)
        self.assertIn("servicedll", result["services"])
        self.assertNotIn("source", result["services"])


class TestBuildSummaryPrompt(unittest.TestCase):
    """Tests for prompts.build_summary_prompt."""

    def test_fills_template(self) -> None:
        from app.analyzer.prompts import build_summary_prompt
        template = (
            "Context: {{investigation_context}}\n"
            "Priority: {{priority_directives}}\n"
            "IOC: {{ioc_targets}}\n"
            "Host: {{hostname}}\nOS: {{os_version}}\nDomain: {{domain}}\n"
            "Findings:\n{{per_artifact_findings}}\n"
        )
        result = build_summary_prompt(
            summary_prompt_template=template,
            investigation_context="Test context",
            per_artifact_results=[
                {"artifact_key": "runkeys", "artifact_name": "RunKeys", "analysis": "Found stuff"},
            ],
            metadata_map={"hostname": "host1", "os_version": "Win10", "domain": "corp"},
        )
        self.assertIn("Context: Test context", result)
        self.assertIn("Host: host1", result)
        self.assertIn("### RunKeys (runkeys)", result)

    def test_empty_results(self) -> None:
        from app.analyzer.prompts import build_summary_prompt
        result = build_summary_prompt(
            summary_prompt_template="{{per_artifact_findings}}",
            investigation_context="ctx",
            per_artifact_results=[],
            metadata_map={},
        )
        self.assertIn("No per-artifact findings available", result)

    def test_missing_metadata_uses_unknown(self) -> None:
        from app.analyzer.prompts import build_summary_prompt
        template = "Host: {{hostname}}\nOS: {{os_version}}\nDomain: {{domain}}"
        result = build_summary_prompt(
            summary_prompt_template=template,
            investigation_context="ctx",
            per_artifact_results=[],
            metadata_map={},
        )
        self.assertIn("Host: Unknown", result)
        self.assertIn("OS: Unknown", result)

    def test_os_type_placeholder_filled(self) -> None:
        """The {{os_type}} placeholder should be filled from metadata_map."""
        from app.analyzer.prompts import build_summary_prompt
        template = "OS Type: {{os_type}} | Version: {{os_version}}"
        result = build_summary_prompt(
            summary_prompt_template=template,
            investigation_context="ctx",
            per_artifact_results=[],
            metadata_map={"os_type": "linux", "os_version": "Ubuntu 22.04"},
        )
        self.assertIn("OS Type: linux", result)
        self.assertIn("Version: Ubuntu 22.04", result)


if __name__ == "__main__":
    unittest.main()
