from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from app.ai_providers import AIProviderError
from app.analyzer import ForensicAnalyzer
from app.case_logging import case_log_context, register_case_log_handler, unregister_case_log_handler


class FakeAuditLogger:
    def __init__(self) -> None:
        self.entries: list[tuple[str, dict]] = []

    def log(self, action: str, details: dict) -> None:
        self.entries.append((action, details))


class FakeProvider:
    def __init__(self, responses: list[str] | None = None, fail_calls: set[int] | None = None) -> None:
        self.responses = list(responses or ["stub-response"])
        self.fail_calls = set(fail_calls or set())
        self.calls: list[dict[str, str]] = []
        self.call_count = 0

    def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        call_index = self.call_count
        self.call_count += 1
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "max_tokens": str(max_tokens),
            }
        )
        if call_index in self.fail_calls:
            raise AIProviderError(f"provider-failure-{call_index}")
        if call_index < len(self.responses):
            return self.responses[call_index]
        return self.responses[-1]

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "fake", "model": "fake-model-1"}


class FakeAttachmentProvider(FakeProvider):
    def __init__(self, responses: list[str] | None = None) -> None:
        super().__init__(responses=responses)
        self.attachments_calls: list[list[dict[str, str]]] = []

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[dict[str, str]] | None,
        max_tokens: int = 4096,
    ) -> str:
        self.attachments_calls.append(list(attachments or []))
        return self.analyze(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=max_tokens)


class AnalyzerTests(unittest.TestCase):
    def _write_prompt_template(self, prompts_dir: Path) -> None:
        template = (
            "Priority={{priority_directives}}\n"
            "IOC={{ioc_targets}}\n"
            "Key={{artifact_key}}\n"
            "Artifact={{artifact_name}}\n"
            "Desc={{artifact_description}}\n"
            "Context={{investigation_context}}\n"
            "Total={{total_records}}\n"
            "Start={{time_range_start}}\n"
            "End={{time_range_end}}\n"
            "Stats:\n{{statistics}}\n"
            "Instructions={{analysis_instructions}}\n"
            "Data:\n{{data_csv}}\n"
        )
        prompts_dir.mkdir(parents=True, exist_ok=True)
        (prompts_dir / "artifact_analysis.md").write_text(template, encoding="utf-8")
        (prompts_dir / "system_prompt.md").write_text("SYSTEM PROMPT", encoding="utf-8")
        (prompts_dir / "summary_prompt.md").write_text(
            (
                "SummaryPriority={{priority_directives}}\n"
                "SummaryIOC={{ioc_targets}}\n"
                "SummaryContext={{investigation_context}}\n"
                "Host={{hostname}}\n"
                "OS={{os_version}}\n"
                "Domain={{domain}}\n"
                "Findings:\n{{per_artifact_findings}}\n"
            ),
            encoding="utf-8",
        )

    def _write_artifact_instruction_prompt(self, prompts_dir: Path, artifact_key: str, text: str) -> None:
        instruction_dir = prompts_dir / "artifact_instructions"
        instruction_dir.mkdir(parents=True, exist_ok=True)
        (instruction_dir / f"{artifact_key}.md").write_text(text, encoding="utf-8")

    def test_load_prompt_template_reads_template(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            prompts_dir = Path(temp_dir) / "prompts"
            self._write_prompt_template(prompts_dir)

            analyzer = ForensicAnalyzer(prompts_dir=prompts_dir)
            prompt = analyzer._load_prompt_template("artifact_analysis.md", default="fallback")

        self.assertIn("Artifact={{artifact_name}}", prompt)
        self.assertIn("Data:", prompt)

    def test_extract_dates_from_context_supports_required_formats(self) -> None:
        analyzer = ForensicAnalyzer()
        context = (
            "Investigation window includes 2026-01-15, 16-01-2026, 17/01/2026, "
            "and January 18, 2026."
        )

        dates = analyzer._extract_dates_from_context(context)
        date_strings = [value.date().isoformat() for value in dates]

        self.assertEqual(
            date_strings,
            ["2026-01-15", "2026-01-16", "2026-01-17", "2026-01-18"],
        )

    def test_extract_ioc_targets_from_context(self) -> None:
        analyzer = ForensicAnalyzer()
        context = (
            "Investigate IOC 198.51.100.25, https://evil.example/path, "
            "hash 44d88612fea8a8f36de82e1278abb02f, "
            "email attacker@example.net, "
            r"path C:\Users\Public\stage.exe and tool mimikatz."
        )

        iocs = analyzer._extract_ioc_targets(context)

        self.assertIn("IPv4", iocs)
        self.assertIn("198.51.100.25", iocs["IPv4"])
        self.assertIn("URLs", iocs)
        self.assertIn("https://evil.example/path", iocs["URLs"])
        self.assertIn("Hashes", iocs)
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", iocs["Hashes"])
        self.assertIn("Emails", iocs)
        self.assertIn("attacker@example.net", iocs["Emails"])
        self.assertIn("FilePaths", iocs)
        self.assertIn(r"C:\Users\Public\stage.exe", iocs["FilePaths"])
        self.assertIn("SuspiciousTools", iocs)
        self.assertIn("mimikatz", iocs["SuspiciousTools"])

    def test_extract_ioc_targets_does_not_treat_executable_name_as_domain(self) -> None:
        analyzer = ForensicAnalyzer()
        context = "Look for abc.exe execution and related activity."

        iocs = analyzer._extract_ioc_targets(context)

        self.assertIn("FileNames", iocs)
        self.assertIn("abc.exe", [value.lower() for value in iocs["FileNames"]])
        self.assertNotIn("Domains", iocs)

    def test_extract_dates_from_context_supports_textual_day_ranges(self) -> None:
        analyzer = ForensicAnalyzer()
        context = (
            "We suspect unauthorized access between January 1-15, 2026 and "
            "January 20 to 22, 2026."
        )

        dates = analyzer._extract_dates_from_context(context)
        date_strings = [value.date().isoformat() for value in dates]

        self.assertEqual(
            date_strings,
            ["2026-01-01", "2026-01-15", "2026-01-20", "2026-01-22"],
        )

    def test_compute_statistics_reports_counts_time_range_and_top_values(self) -> None:
        analyzer = ForensicAnalyzer()
        rows = [
            {"ts": "2026-01-15T01:00:00+00:00", "name": "alpha"},
            {"ts": "2026-01-16T01:00:00+00:00", "name": "alpha"},
            {"ts": "2026-01-17T01:00:00+00:00", "name": "beta"},
        ]

        stats, min_time, max_time = analyzer._compute_statistics(rows=rows, columns=["name"])

        self.assertIn("Record count: 3", stats)
        self.assertIn("Time range start: 2026-01-15T01:00:00", stats)
        self.assertIn("Time range end: 2026-01-17T01:00:00", stats)
        self.assertIn("- name:", stats)
        self.assertIn("2x alpha", stats)
        self.assertIn("1x beta", stats)
        self.assertIsNotNone(min_time)
        self.assertIsNotNone(max_time)

    def test_prepare_artifact_data_builds_filled_prompt_with_filtered_rows(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "MünchenEntry",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2025-08-01T12:00:00+00:00",
                        "name": "OldEntry",
                        "command": r"C:\Program Files\Legit\app.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on activity around January 15, 2026.",
            )

        self.assertIn("Artifact=Run/RunOnce Keys", filled_prompt)
        self.assertIn("Key=runkeys", filled_prompt)
        self.assertIn("Total=1", filled_prompt)
        self.assertIn("Rows kept after filter: 1 of 2.", filled_prompt)
        self.assertIn("row_ref,ts,name,command", filled_prompt)
        self.assertIn("MünchenEntry", filled_prompt)
        self.assertNotIn("OldEntry", filled_prompt)
        self.assertNotIn("{{artifact_name}}", filled_prompt)
        self.assertNotIn("{{data_csv}}", filled_prompt)

    def test_prepare_artifact_data_includes_priority_directives_and_ioc_targets(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Check 198.51.100.25 and tool mimikatz in January 2026.",
            )

        self.assertIn("Priority=1. Treat the user investigation context as highest priority", filled_prompt)
        self.assertIn("IOC=- IPv4: 198.51.100.25", filled_prompt)
        self.assertIn("Key=runkeys", filled_prompt)
        self.assertIn("SuspiciousTools: mimikatz", filled_prompt)
        self.assertIn("## Final Context Reminder (Do Not Ignore)", filled_prompt)
        self.assertIn("- Artifact key: runkeys", filled_prompt)

    def test_prepare_artifact_data_uses_artifact_instruction_prompt_file(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)
            self._write_artifact_instruction_prompt(
                prompts_dir=prompts_dir,
                artifact_key="runkeys",
                text="RUNKEYS-SPECIFIC-INSTRUCTIONS",
            )

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

        self.assertIn("Instructions=RUNKEYS-SPECIFIC-INSTRUCTIONS", filled_prompt)

    def test_prepare_artifact_data_uses_normalized_artifact_instruction_prompt(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)
            self._write_artifact_instruction_prompt(
                prompts_dir=prompts_dir,
                artifact_key="evtx",
                text="EVTX-SPECIFIC-INSTRUCTIONS",
            )

            csv_path = temp_path / "evtx_security.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "EventID", "Channel"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "EventID": "4688",
                        "Channel": "Security",
                    }
                )

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx_Security": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="evtx_Security",
                investigation_context="Focus on January 15, 2026.",
            )

        self.assertIn("Instructions=EVTX-SPECIFIC-INSTRUCTIONS", filled_prompt)

    def test_prepare_artifact_data_keeps_rows_without_timestamp_when_context_dates_exist(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "InRange",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "",
                        "name": "NoTimestamp",
                        "command": r"C:\Users\Public\mystery.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2025-08-01T12:00:00+00:00",
                        "name": "OldEntry",
                        "command": r"C:\Program Files\Legit\app.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on activity around January 15, 2026.",
            )

        # Rows without timestamps are kept (not dropped) — they may contain
        # forensically relevant evidence that simply lacks a write timestamp.
        self.assertIn("Rows kept after filter: 2 of 3.", filled_prompt)
        self.assertIn("Rows without parseable timestamp (included unfiltered): 1.", filled_prompt)
        self.assertIn("InRange", filled_prompt)
        self.assertIn("NoTimestamp", filled_prompt)
        self.assertNotIn("OldEntry", filled_prompt)

    def test_prepare_artifact_data_normalizes_aware_timestamps_before_date_filtering(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "AwareEntry",
                        "command": r"C:\Users\Public\aware.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            aware_timestamp = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
            with patch.object(analyzer, "_extract_row_datetime", return_value=aware_timestamp):
                filled_prompt = analyzer._prepare_artifact_data(
                    artifact_key="runkeys",
                    investigation_context="Focus on activity around January 15, 2026.",
                )

        self.assertIn("Rows kept after filter: 1 of 1.", filled_prompt)
        self.assertIn("AwareEntry", filled_prompt)

    def test_explicit_step2_date_range_filters_mft_prompt_rows(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "mft.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "path", "entry"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-12T08:00:00+00:00",
                        "path": r"C:\Users\Public\in-range.txt",
                        "entry": "InRange",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2025-11-30T08:00:00+00:00",
                        "path": r"C:\Users\Public\old.txt",
                        "entry": "OutOfRange",
                    }
                )

            fake_provider = FakeProvider(responses=["mft-analysis", "summary-analysis"])
            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    artifact_csv_paths={"mft": csv_path},
                    prompts_dir=prompts_dir,
                    random_seed=7,
                )
                analyzer.run_full_analysis(
                    artifact_keys=["mft"],
                    investigation_context="",
                    metadata={
                        "analysis_date_range": {
                            "start_date": "2026-01-01",
                            "end_date": "2026-01-31",
                        }
                    },
                )

        mft_prompt = fake_provider.calls[0]["user_prompt"]
        self.assertIn(
            "Date filter applied from Step 2 selection: 2026-01-01 to 2026-01-31 (inclusive).",
            mft_prompt,
        )
        self.assertIn("Rows kept after filter: 1 of 2.", mft_prompt)
        self.assertIn(r"C:\Users\Public\in-range.txt", mft_prompt)
        self.assertNotIn(r"C:\Users\Public\old.txt", mft_prompt)

    def test_explicit_step2_date_range_does_not_filter_non_target_artifacts(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-12T08:00:00+00:00",
                        "name": "InRange",
                        "command": r"C:\Users\Public\in-range.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2025-11-30T08:00:00+00:00",
                        "name": "OutOfRange",
                        "command": r"C:\Users\Public\old.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            fake_provider = FakeProvider(responses=["runkeys-analysis", "summary-analysis"])
            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    artifact_csv_paths={"runkeys": csv_path},
                    prompts_dir=prompts_dir,
                    random_seed=7,
                )
                analyzer.run_full_analysis(
                    artifact_keys=["runkeys"],
                    investigation_context="",
                    metadata={
                        "analysis_date_range": {
                            "start_date": "2026-01-01",
                            "end_date": "2026-01-31",
                        }
                    },
                )

        runkeys_prompt = fake_provider.calls[0]["user_prompt"]
        self.assertIn("Total=2", runkeys_prompt)
        self.assertIn("InRange", runkeys_prompt)
        self.assertIn("OutOfRange", runkeys_prompt)
        self.assertNotIn("Date filter applied from Step 2 selection", runkeys_prompt)

    def test_init_loads_prompt_templates_and_creates_provider(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            prompts_dir = Path(temp_dir) / "prompts"
            self._write_prompt_template(prompts_dir)
            fake_provider = FakeProvider()
            audit = FakeAuditLogger()

            with patch("app.analyzer.create_provider", return_value=fake_provider) as create_provider_mock:
                analyzer = ForensicAnalyzer(
                    case_dir=temp_dir,
                    config={"ai": {"provider": "local", "local": {"model": "fake-model-1"}}},
                    audit_logger=audit,
                    prompts_dir=prompts_dir,
                )

        create_provider_mock.assert_called_once()
        self.assertEqual(analyzer.system_prompt, "SYSTEM PROMPT")
        self.assertIn("SummaryContext={{investigation_context}}", analyzer.summary_prompt_template)
        self.assertEqual(analyzer.model_info["provider"], "fake")
        self.assertEqual(analyzer.model_info["model"], "fake-model-1")

    def test_analyze_artifact_calls_provider_and_logs_audit(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            fake_provider = FakeProvider(responses=["artifact-analysis-output"])
            audit = FakeAuditLogger()
            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=temp_dir,
                    config={"ai": {"provider": "local"}},
                    audit_logger=audit,
                    artifact_csv_paths={"runkeys": csv_path},
                    prompts_dir=prompts_dir,
                )
                result = analyzer.analyze_artifact(
                    artifact_key="runkeys",
                    investigation_context="Focus on January 15, 2026.",
                )

        self.assertEqual(result["artifact_key"], "runkeys")
        self.assertEqual(result["artifact_name"], "Run/RunOnce Keys")
        self.assertEqual(result["analysis"], "artifact-analysis-output")
        self.assertEqual(result["model"], "fake-model-1")
        self.assertEqual(len(fake_provider.calls), 1)
        self.assertEqual(fake_provider.calls[0]["system_prompt"], "SYSTEM PROMPT")
        self.assertIn("Artifact=Run/RunOnce Keys", fake_provider.calls[0]["user_prompt"])
        self.assertEqual(audit.entries[0][0], "analysis_started")
        self.assertEqual(audit.entries[-1][0], "analysis_completed")

    def test_analyze_artifact_passes_csv_attachment_when_provider_supports_it(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key", "username"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "username": "testuser",
                    }
                )

            fake_provider = FakeAttachmentProvider(responses=["artifact-analysis-output"])
            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=temp_dir,
                    config={"ai": {"provider": "local"}},
                    audit_logger=FakeAuditLogger(),
                    artifact_csv_paths={"runkeys": csv_path},
                    prompts_dir=prompts_dir,
                )
                result = analyzer.analyze_artifact(
                    artifact_key="runkeys",
                    investigation_context="Focus on January 15, 2026.",
                )
            expected_path = temp_path / "parsed_deduplicated" / "runkeys.csv"
            dedup_exists = expected_path.exists()
            projected_header = expected_path.read_text(encoding="utf-8").splitlines()[0]

        self.assertEqual(result["analysis"], "artifact-analysis-output")
        self.assertEqual(len(fake_provider.attachments_calls), 1)
        self.assertEqual(len(fake_provider.attachments_calls[0]), 1)
        self.assertEqual(fake_provider.attachments_calls[0][0]["path"], str(expected_path))
        self.assertTrue(dedup_exists)
        self.assertEqual(projected_header, "ts,name,command,username")
        self.assertEqual(fake_provider.attachments_calls[0][0]["mime_type"], "text/csv")

    def test_prepare_artifact_data_deduplicates_rows_and_writes_deduplicated_csv(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "record_id", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "record_id": "100",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:01:00+00:00",
                        "record_id": "101",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:02:00+00:00",
                        "record_id": "102",
                        "name": "EntryB",
                        "command": r"C:\Users\Public\tool.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                case_dir=temp_dir,
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

            dedup_csv_path = temp_path / "parsed_deduplicated" / "runkeys.csv"
            dedup_exists = dedup_csv_path.exists()
            with dedup_csv_path.open("r", newline="", encoding="utf-8") as handle:
                dedup_rows = list(csv.DictReader(handle))

        self.assertIn("Rows removed as timestamp/ID-only duplicates: 1.", filled_prompt)
        self.assertIn("Rows annotated with deduplication comment: 1.", filled_prompt)
        self.assertIn("_dedup_comment", filled_prompt)
        self.assertIn("Deduplicated 1 records with matching event data and different timestamp/ID.", filled_prompt)
        self.assertIn("Total=2", filled_prompt)
        self.assertTrue(dedup_exists)
        self.assertEqual(len(dedup_rows), 2)
        self.assertIn("Deduplicated 1 records", dedup_rows[0].get("_dedup_comment", ""))

    def test_prepare_artifact_data_deduplicates_using_selected_columns_only(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["ts", "name", "command", "username", "key"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "username": "alice",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:01:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "username": "alice",
                        "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:02:00+00:00",
                        "name": "EntryB",
                        "command": r"C:\Users\Public\tool.exe",
                        "username": "alice",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                case_dir=temp_dir,
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

            dedup_csv_path = temp_path / "parsed_deduplicated" / "runkeys.csv"
            with dedup_csv_path.open("r", newline="", encoding="utf-8") as handle:
                dedup_reader = csv.DictReader(handle)
                dedup_rows = list(dedup_reader)
                dedup_header = list(dedup_reader.fieldnames or [])

        self.assertIn("Rows removed as timestamp/ID-only duplicates: 1.", filled_prompt)
        self.assertIn("Total=2", filled_prompt)
        self.assertNotIn("key", dedup_header)
        self.assertEqual(
            dedup_header,
            ["ts", "name", "command", "username", "_dedup_comment"],
        )
        self.assertEqual(len(dedup_rows), 2)

    def test_prepare_artifact_data_can_disable_deduplication(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "record_id", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "record_id": "100",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:01:00+00:00",
                        "record_id": "101",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                case_dir=temp_dir,
                config={
                    "analysis": {"artifact_deduplication_enabled": False},
                },
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

            dedup_csv_path = temp_path / "parsed_deduplicated" / "runkeys.csv"

        self.assertIn("Total=2", filled_prompt)
        self.assertNotIn("Rows removed as timestamp/ID-only duplicates", filled_prompt)
        self.assertNotIn("_dedup_comment", filled_prompt)
        self.assertFalse(dedup_csv_path.exists())

    def test_prepare_artifact_data_uses_external_ai_column_projection_config(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            projection_path = temp_path / "artifact_ai_columns.yaml"
            projection_path.write_text(
                (
                    "artifact_ai_columns:\n"
                    "  runkeys:\n"
                    "    - ts\n"
                    "    - name\n"
                ),
                encoding="utf-8",
            )

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["ts", "name", "command", "username", "key"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "username": "alice",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            analyzer = ForensicAnalyzer(
                case_dir=temp_dir,
                config={
                    "analysis": {
                        "artifact_deduplication_enabled": False,
                        "artifact_ai_columns_config_path": str(projection_path),
                    }
                },
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on suspicious startup entries.",
            )

            projected_csv_path = temp_path / "parsed_deduplicated" / "runkeys.csv"
            projected_header = projected_csv_path.read_text(encoding="utf-8").splitlines()[0]

        self.assertIn("row_ref,ts,name", filled_prompt)
        self.assertNotIn("row_ref,ts,name,command,username", filled_prompt)
        self.assertIn("AI column projection applied: ts, name.", filled_prompt)
        self.assertEqual(projected_header, "ts,name")

    def test_load_artifact_ai_column_projection_config_logs_warning_on_yaml_error(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            bad_projection_path = temp_path / "artifact_ai_columns.yaml"
            bad_projection_path.write_text(
                (
                    "artifact_ai_columns:\n"
                    "  runkeys: [ts, name\n"
                ),
                encoding="utf-8",
            )

            with patch("app.analyzer.create_provider", return_value=FakeProvider()):
                with self.assertLogs("app.analyzer", level="WARNING") as captured_logs:
                    analyzer = ForensicAnalyzer(
                        config={
                            "analysis": {
                                "artifact_ai_columns_config_path": str(bad_projection_path),
                            }
                        }
                    )

        self.assertEqual(analyzer.artifact_ai_column_projections, {})
        emitted = "\n".join(captured_logs.output)
        self.assertIn("Failed to load AI column projection config", emitted)
        self.assertIn("AI column projection is disabled", emitted)
        self.assertIn(str(bad_projection_path), emitted)

    def test_case_logger_writes_projection_warnings_to_case_logs_folder(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            case_id = "case-logging-test"
            log_path = register_case_log_handler(case_id=case_id, case_dir=temp_path)
            bad_projection_path = temp_path / "artifact_ai_columns.yaml"
            bad_projection_path.write_text(
                (
                    "artifact_ai_columns:\n"
                    "  runkeys: [ts, name\n"
                ),
                encoding="utf-8",
            )

            try:
                with patch("app.analyzer.create_provider", return_value=FakeProvider()):
                    with case_log_context(case_id):
                        analyzer = ForensicAnalyzer(
                            case_dir=temp_path,
                            config={
                                "analysis": {
                                    "artifact_ai_columns_config_path": str(bad_projection_path),
                                }
                            },
                        )
                self.assertEqual(analyzer.artifact_ai_column_projections, {})
                self.assertTrue(log_path.exists())
                contents = log_path.read_text(encoding="utf-8")
            finally:
                unregister_case_log_handler(case_id)

        self.assertIn("Failed to load AI column projection config", contents)
        self.assertIn("AI column projection is disabled", contents)
        self.assertIn(str(bad_projection_path), contents)

    def test_analyze_artifact_uses_configured_advanced_analysis_settings(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "runkeys.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "name": "EntryA",
                        "command": r"C:\Users\Public\evil.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-01T12:00:00+00:00",
                        "name": "OldEntry",
                        "command": r"C:\Users\Public\old.exe",
                        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    }
                )

            fake_provider = FakeProvider(responses=["artifact-analysis-output"])
            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=temp_dir,
                    config={
                        "ai": {"provider": "local"},
                        "analysis": {
                            "date_buffer_days": 2,
                            "ai_max_tokens": 1234,
                        },
                    },
                    audit_logger=FakeAuditLogger(),
                    artifact_csv_paths={"runkeys": csv_path},
                    prompts_dir=prompts_dir,
                )
                analyzer.analyze_artifact(
                    artifact_key="runkeys",
                    investigation_context="Focus on January 15, 2026.",
                )

        self.assertEqual(len(fake_provider.calls), 1)
        self.assertEqual(fake_provider.calls[0]["max_tokens"], "1234")
        self.assertIn("(+/- 2 days).", fake_provider.calls[0]["user_prompt"])

    def test_run_full_analysis_continues_after_artifact_failure(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            runkeys_csv = temp_path / "runkeys.csv"
            tasks_csv = temp_path / "tasks.csv"
            for csv_path, name in ((runkeys_csv, "RunA"), (tasks_csv, "TaskA")):
                with csv_path.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=["ts", "name", "command", "key"])
                    writer.writeheader()
                    writer.writerow(
                        {
                            "ts": "2026-01-15T12:00:00+00:00",
                            "name": name,
                            "command": r"C:\Users\Public\tool.exe",
                            "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        }
                    )

            fake_provider = FakeProvider(
                responses=[
                    "unused-for-first-call",
                    "tasks-analysis",
                    "summary-analysis",
                ],
                fail_calls={0},
            )
            audit = FakeAuditLogger()
            progress_events: list[tuple[str, str, dict[str, str]]] = []

            def progress_callback(artifact_key: str, status: str, result: dict[str, str]) -> None:
                progress_events.append((artifact_key, status, result))

            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=temp_dir,
                    config={"ai": {"provider": "local"}},
                    audit_logger=audit,
                    artifact_csv_paths={"runkeys": runkeys_csv, "tasks": tasks_csv},
                    prompts_dir=prompts_dir,
                )
                output = analyzer.run_full_analysis(
                    artifact_keys=["runkeys", "tasks"],
                    investigation_context="Focus on January 15, 2026.",
                    metadata={"hostname": "host1", "os_version": "Windows", "domain": "corp.local"},
                    progress_callback=progress_callback,
                )

        self.assertEqual(len(output["per_artifact"]), 2)
        self.assertTrue(output["per_artifact"][0]["analysis"].startswith("Analysis failed: provider-failure-0"))
        self.assertEqual(output["per_artifact"][1]["analysis"], "tasks-analysis")
        self.assertEqual(output["summary"], "summary-analysis")
        self.assertEqual(output["model_info"]["model"], "fake-model-1")
        self.assertEqual(len(progress_events), 2)
        self.assertEqual(progress_events[0][0], "runkeys")
        self.assertEqual(progress_events[0][1], "complete")

    def test_generate_summary_fills_template_and_calls_provider(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            prompts_dir = Path(temp_dir) / "prompts"
            self._write_prompt_template(prompts_dir)

            fake_provider = FakeProvider(responses=["summary-output"])
            with patch("app.analyzer.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=temp_dir,
                    config={"ai": {"provider": "local"}},
                    audit_logger=FakeAuditLogger(),
                    prompts_dir=prompts_dir,
                )

                summary = analyzer.generate_summary(
                    per_artifact_results=[
                        {
                            "artifact_key": "runkeys",
                            "artifact_name": "Run/RunOnce Keys",
                            "analysis": "Found suspicious autorun entry.",
                            "model": "fake-model-1",
                        }
                    ],
                    investigation_context="Investigate persistence",
                    metadata={"hostname": "host1", "os_version": "Windows", "domain": "corp.local"},
                )

        self.assertEqual(summary, "summary-output")
        self.assertEqual(len(fake_provider.calls), 1)
        self.assertEqual(fake_provider.calls[0]["system_prompt"], "SYSTEM PROMPT")
        self.assertIn("SummaryContext=Investigate persistence", fake_provider.calls[0]["user_prompt"])
        self.assertIn("### Run/RunOnce Keys (runkeys)", fake_provider.calls[0]["user_prompt"])


    def test_dedup_does_not_collapse_rows_differing_only_in_eventid(self) -> None:
        """EventID is a semantic field — rows with different EventIDs are distinct events."""
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            csv_path = temp_path / "evtx_security.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["ts", "EventID", "Channel", "SubjectUserName"]
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:00:00+00:00",
                        "EventID": "4624",
                        "Channel": "Security",
                        "SubjectUserName": "admin",
                    }
                )
                writer.writerow(
                    {
                        "ts": "2026-01-15T12:01:00+00:00",
                        "EventID": "4688",
                        "Channel": "Security",
                        "SubjectUserName": "admin",
                    }
                )

            analyzer = ForensicAnalyzer(
                case_dir=temp_dir,
                artifact_csv_paths={"evtx_Security": csv_path},
                prompts_dir=prompts_dir,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="evtx_Security",
                investigation_context="Focus on January 15, 2026.",
            )

        # Both rows must survive — they have different EventIDs and are
        # genuinely different events.  The old code incorrectly treated
        # EventID as a variant column and would collapse them.
        self.assertIn("Total=2", filled_prompt)
        self.assertIn("4624", filled_prompt)
        self.assertIn("4688", filled_prompt)
        self.assertIn("Rows removed as timestamp/ID-only duplicates: 0.", filled_prompt)

    def test_dedup_does_not_collapse_rows_differing_only_in_process_id(self) -> None:
        """ProcessID distinguishes processes — must not be treated as a dedup variant."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"ts": "2026-01-15T12:00:00", "ProcessID": "1234", "name": "cmd.exe"},
            {"ts": "2026-01-15T12:01:00", "ProcessID": "5678", "name": "cmd.exe"},
        ]
        columns = ["ts", "ProcessID", "name"]

        kept, out_cols, removed, annotated, variant_cols = (
            analyzer._deduplicate_rows_for_analysis(rows=rows, columns=columns)
        )

        self.assertEqual(len(kept), 2)
        self.assertEqual(removed, 0)

    def test_dedup_collapses_rows_differing_only_in_record_id_and_timestamp(self) -> None:
        """record_id is a safe auto-increment ID — rows matching on all other fields collapse."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"ts": "2026-01-15T12:00:00", "record_id": "100", "name": "EntryA", "command": "evil.exe"},
            {"ts": "2026-01-15T12:01:00", "record_id": "101", "name": "EntryA", "command": "evil.exe"},
            {"ts": "2026-01-15T12:02:00", "record_id": "102", "name": "EntryB", "command": "tool.exe"},
        ]
        columns = ["ts", "record_id", "name", "command"]

        kept, out_cols, removed, annotated, variant_cols = (
            analyzer._deduplicate_rows_for_analysis(rows=rows, columns=columns)
        )

        self.assertEqual(len(kept), 2)
        self.assertEqual(removed, 1)
        self.assertEqual(annotated, 1)
        self.assertIn("_dedup_comment", out_cols)
        self.assertIn("Deduplicated 1 records", kept[0].get("_dedup_comment", ""))

    def test_dedup_removes_exact_duplicate_rows(self) -> None:
        """Fully identical rows (same base + same variant) should also be deduplicated."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"ts": "2026-01-15T12:00:00", "record_id": "100", "name": "EntryA", "command": "evil.exe"},
            {"ts": "2026-01-15T12:00:00", "record_id": "100", "name": "EntryA", "command": "evil.exe"},
        ]
        columns = ["ts", "record_id", "name", "command"]

        kept, out_cols, removed, annotated, variant_cols = (
            analyzer._deduplicate_rows_for_analysis(rows=rows, columns=columns)
        )

        self.assertEqual(len(kept), 1)
        self.assertEqual(removed, 1)

    def test_dedup_safe_identifier_classification(self) -> None:
        """Only auto-incremented record IDs are dedup-safe, not semantic IDs."""
        analyzer = ForensicAnalyzer()

        # These should be dedup-safe (auto-incremented record identifiers)
        self.assertTrue(analyzer._is_dedup_safe_identifier_column("record_id"))
        self.assertTrue(analyzer._is_dedup_safe_identifier_column("RecordID"))
        self.assertTrue(analyzer._is_dedup_safe_identifier_column("entry_id"))
        self.assertTrue(analyzer._is_dedup_safe_identifier_column("index"))

        # These should NOT be dedup-safe (carry forensic meaning)
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("EventID"))
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("event_id"))
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("ProcessID"))
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("process_id"))
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("SessionID"))
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("LogonID"))
        self.assertFalse(analyzer._is_dedup_safe_identifier_column("id"))

    def test_build_full_data_csv_truncates_large_datasets(self) -> None:
        """Inline CSV is truncated with a notice when it exceeds max_chars."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"_row_ref": str(i), "name": f"entry_{i}", "data": "x" * 100}
            for i in range(1, 201)
        ]
        columns = ["name", "data"]

        # With a low limit, output should be truncated
        result = analyzer._build_full_data_csv(rows=rows, columns=columns, max_chars=500)

        self.assertIn("TRUNCATED", result)
        self.assertIn("200 rows", result)
        self.assertIn("attached CSV file", result)
        self.assertLessEqual(len(result), 800)  # truncated + notice

    def test_build_full_data_csv_no_truncation_when_within_limit(self) -> None:
        """Small datasets should not be truncated."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"_row_ref": "1", "name": "entry_1", "data": "hello"},
            {"_row_ref": "2", "name": "entry_2", "data": "world"},
        ]
        columns = ["name", "data"]

        result = analyzer._build_full_data_csv(rows=rows, columns=columns, max_chars=10000)

        self.assertNotIn("TRUNCATED", result)
        self.assertIn("entry_1", result)
        self.assertIn("entry_2", result)

    def test_build_full_data_csv_no_limit_when_max_chars_zero(self) -> None:
        """max_chars=0 means no truncation (backwards compatible)."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"_row_ref": str(i), "name": f"entry_{i}", "data": "x" * 200}
            for i in range(1, 101)
        ]
        columns = ["name", "data"]

        result = analyzer._build_full_data_csv(rows=rows, columns=columns, max_chars=0)

        self.assertNotIn("TRUNCATED", result)
        self.assertIn("entry_100", result)

    def test_timestamp_found_in_csv_uses_preloaded_lookup_keys(self) -> None:
        analyzer = ForensicAnalyzer()
        csv_timestamp_lookup: set[str] = set()
        for value in (
            "2026-01-15T12:00:00+00:00",
            "2026-01-15T13:00:00.123456Z",
            "2026-01-15T14:00:00+02:00",
        ):
            csv_timestamp_lookup.update(analyzer._timestamp_lookup_keys(value))

        self.assertTrue(
            analyzer._timestamp_found_in_csv(
                "2026-01-15T12:00:00Z",
                csv_timestamp_lookup,
            )
        )
        self.assertTrue(
            analyzer._timestamp_found_in_csv(
                "2026-01-15 13:00:00",
                csv_timestamp_lookup,
            )
        )
        self.assertTrue(
            analyzer._timestamp_found_in_csv(
                "2026-01-15T14:00:00",
                csv_timestamp_lookup,
            )
        )
        self.assertFalse(
            analyzer._timestamp_found_in_csv(
                "2026-01-15T20:00:00Z",
                csv_timestamp_lookup,
            )
        )

    def test_dedup_with_generic_id_column_does_not_treat_it_as_variant(self) -> None:
        """A column named just 'id' could be EventID or UserID — not safe for dedup."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"ts": "2026-01-15T12:00:00", "id": "100", "name": "EntryA"},
            {"ts": "2026-01-15T12:01:00", "id": "101", "name": "EntryA"},
        ]
        columns = ["ts", "id", "name"]

        kept, out_cols, removed, annotated, variant_cols = (
            analyzer._deduplicate_rows_for_analysis(rows=rows, columns=columns)
        )

        # 'id' is a base column now, so these rows differ in base data → both kept
        self.assertEqual(len(kept), 2)
        self.assertEqual(removed, 0)
        self.assertNotIn("id", variant_cols)


if __name__ == "__main__":
    unittest.main()

