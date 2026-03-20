from __future__ import annotations

import csv
import os
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
        small_context_template = template.replace("Stats:\n{{statistics}}\n", "")
        prompts_dir.mkdir(parents=True, exist_ok=True)
        (prompts_dir / "artifact_analysis.md").write_text(template, encoding="utf-8")
        (prompts_dir / "artifact_analysis_small_context.md").write_text(
            small_context_template,
            encoding="utf-8",
        )
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

    def test_prepare_artifact_data_omits_statistics_section_for_small_context_window(self) -> None:
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
                config={"analysis": {"ai_max_tokens": 63999}},
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

        self.assertIn("Total=1", filled_prompt)
        self.assertIn("EntryA", filled_prompt)
        self.assertNotIn("Stats:", filled_prompt)
        self.assertNotIn("Record count:", filled_prompt)
        self.assertNotIn("Rows removed as timestamp/ID-only duplicates:", filled_prompt)

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

    def test_prepare_artifact_data_uses_small_context_prompt_template(self) -> None:
        with TemporaryDirectory(prefix="aift-analyzer-test-") as temp_dir:
            temp_path = Path(temp_dir)
            prompts_dir = temp_path / "prompts"
            self._write_prompt_template(prompts_dir)

            (prompts_dir / "artifact_analysis_small_context.md").write_text(
                (
                    "SMALL-CONTEXT-TEMPLATE\n"
                    "Key={{artifact_key}}\n"
                    "Total={{total_records}}\n"
                    "Data:\n{{data_csv}}\n"
                ),
                encoding="utf-8",
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
                config={"analysis": {"ai_max_tokens": 63999}},
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

        self.assertIn("SMALL-CONTEXT-TEMPLATE", filled_prompt)
        self.assertIn("Total=1", filled_prompt)
        self.assertNotIn("Stats:", filled_prompt)
        self.assertNotIn("Record count:", filled_prompt)

    def test_prepare_artifact_data_uses_user_configured_shortened_prompt_cutoff(self) -> None:
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
                config={
                    "analysis": {
                        "ai_max_tokens": 5000,
                        "shortened_prompt_cutoff_tokens": 4000,
                    }
                },
                artifact_csv_paths={"runkeys": csv_path},
                prompts_dir=prompts_dir,
                random_seed=7,
            )
            filled_prompt = analyzer._prepare_artifact_data(
                artifact_key="runkeys",
                investigation_context="Focus on January 15, 2026.",
            )

        self.assertIn("Stats:", filled_prompt)
        self.assertIn("Record count: 1", filled_prompt)

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
            with patch("app.analyzer.data_prep.extract_row_datetime", return_value=aware_timestamp):
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
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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

            with patch("app.analyzer.core.create_provider", return_value=fake_provider) as create_provider_mock:
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
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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
        self.assertEqual(projected_header, "row_ref,ts,name,command,username")
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
            ["row_ref", "ts", "name", "command", "username", "_dedup_comment"],
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
        self.assertEqual(projected_header, "row_ref,ts,name")

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

            with patch("app.analyzer.core.create_provider", return_value=FakeProvider()):
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
                with patch("app.analyzer.core.create_provider", return_value=FakeProvider()):
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
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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
        # ai_max_tokens is the context window; the provider receives 20% for the response.
        expected_response_tokens = str(max(1, int(1234 * 0.2)))
        self.assertEqual(fake_provider.calls[0]["max_tokens"], expected_response_tokens)
        user_prompt = fake_provider.calls[0]["user_prompt"]
        # With date_buffer_days=2, only the Jan-15 row survives the filter;
        # the Jan-01 row is outside the ±2 day window.
        self.assertIn("EntryA", user_prompt)
        self.assertNotIn("OldEntry", user_prompt)

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

            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
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

    def test_build_full_data_csv_never_truncates(self) -> None:
        """Full CSV is always produced without truncation (DFIR requires all rows)."""
        analyzer = ForensicAnalyzer()
        rows = [
            {"_row_ref": str(i), "name": f"entry_{i}", "data": "x" * 200}
            for i in range(1, 201)
        ]
        columns = ["name", "data"]

        result = analyzer._build_full_data_csv(rows=rows, columns=columns)

        self.assertNotIn("TRUNCATED", result)
        self.assertIn("entry_1", result)
        self.assertIn("entry_200", result)

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


class PathResolutionTests(unittest.TestCase):
    """Verify that ForensicAnalyzer resolves paths relative to PROJECT_ROOT,
    not the current working directory."""

    def test_default_prompts_dir_is_project_root_based(self) -> None:
        """When no prompts_dir is given, it should point to PROJECT_ROOT/prompts
        regardless of the CWD."""
        from app.analyzer import PROJECT_ROOT

        with TemporaryDirectory(prefix="aift-cwd-test-") as fake_cwd:
            with patch("os.getcwd", return_value=fake_cwd):
                analyzer = ForensicAnalyzer()

        expected = PROJECT_ROOT / "prompts"
        self.assertEqual(analyzer.prompts_dir, expected)

    def test_default_prompts_dir_loads_real_prompt_files(self) -> None:
        """The default prompts_dir should contain the actual prompt templates
        shipped with the project."""
        from app.analyzer import PROJECT_ROOT

        analyzer = ForensicAnalyzer()
        self.assertTrue(
            (analyzer.prompts_dir / "system_prompt.md").exists(),
            "system_prompt.md should be found via the default prompts_dir",
        )
        self.assertTrue(
            (analyzer.prompts_dir / "artifact_analysis.md").exists(),
            "artifact_analysis.md should be found via the default prompts_dir",
        )

    def test_explicit_prompts_dir_is_respected(self) -> None:
        with TemporaryDirectory(prefix="aift-prompts-test-") as temp_dir:
            custom = Path(temp_dir) / "my_prompts"
            custom.mkdir()
            analyzer = ForensicAnalyzer(prompts_dir=custom)
            self.assertEqual(analyzer.prompts_dir, custom)

    def test_artifact_ai_columns_config_resolves_to_project_root(self) -> None:
        """The relative artifact_ai_columns_config_path should resolve against
        PROJECT_ROOT, not CWD, when the file only exists in the project tree."""
        from app.analyzer import PROJECT_ROOT

        with TemporaryDirectory(prefix="aift-cwd-test-") as fake_cwd:
            with patch("os.getcwd", return_value=fake_cwd):
                analyzer = ForensicAnalyzer()
                resolved = analyzer._resolve_artifact_ai_columns_config_path()

        self.assertTrue(
            str(resolved).startswith(str(PROJECT_ROOT)),
            f"Expected path under PROJECT_ROOT ({PROJECT_ROOT}), got {resolved}",
        )
        self.assertNotIn(
            fake_cwd,
            str(resolved),
            "Resolved path should NOT reference the fake CWD",
        )

    def test_artifact_ai_columns_config_does_not_use_cwd(self) -> None:
        """Even if a matching file exists in CWD, it should NOT be preferred
        over the PROJECT_ROOT copy."""
        from app.analyzer import PROJECT_ROOT

        with TemporaryDirectory(prefix="aift-cwd-test-") as fake_cwd:
            # Create a decoy file in the fake CWD.
            decoy_dir = Path(fake_cwd) / "config"
            decoy_dir.mkdir()
            decoy_file = decoy_dir / "artifact_ai_columns.yaml"
            decoy_file.write_text("decoy: true", encoding="utf-8")

            with patch("os.getcwd", return_value=fake_cwd):
                analyzer = ForensicAnalyzer()
                resolved = analyzer._resolve_artifact_ai_columns_config_path()

        self.assertNotEqual(
            resolved,
            decoy_file,
            "Should not resolve to a file in CWD",
        )


class AppFactoryPathResolutionTests(unittest.TestCase):
    """Verify that create_app stores an absolute config path."""

    def test_create_app_stores_absolute_config_path(self) -> None:
        from app import create_app
        from app.config import PROJECT_ROOT

        app = create_app()
        stored_path = app.config.get("AIFT_CONFIG_PATH", "")
        self.assertTrue(
            Path(stored_path).is_absolute() or str(PROJECT_ROOT) in stored_path,
            f"AIFT_CONFIG_PATH should be absolute, got: {stored_path}",
        )

    def test_create_app_with_explicit_path_stores_that_path(self) -> None:
        from app import create_app

        with TemporaryDirectory(prefix="aift-factory-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            app = create_app(str(config_path))
            self.assertEqual(app.config["AIFT_CONFIG_PATH"], str(config_path.resolve()))

    def test_create_app_relative_path_becomes_absolute(self) -> None:
        """A relative custom config_path must be resolved to an absolute path."""
        from app import create_app

        app = create_app("relative/config.yaml")
        stored = app.config["AIFT_CONFIG_PATH"]
        self.assertTrue(
            Path(stored).is_absolute(),
            f"AIFT_CONFIG_PATH should be absolute, got: {stored}",
        )
        self.assertTrue(
            stored.endswith("relative/config.yaml".replace("/", os.sep))
            or stored.endswith("relative\\config.yaml"),
            f"Resolved path should end with the original relative suffix, got: {stored}",
        )


class TestMatchColumnName(unittest.TestCase):
    """Tests for ForensicAnalyzer._match_column_name static method."""

    def test_exact_match(self) -> None:
        status, header = ForensicAnalyzer._match_column_name(
            "SourceFilename", ["ts", "SourceFilename", "Path"]
        )
        self.assertEqual(status, "exact")
        self.assertEqual(header, "SourceFilename")

    def test_exact_match_with_whitespace(self) -> None:
        status, header = ForensicAnalyzer._match_column_name(
            "  SourceFilename  ", ["SourceFilename", "Path"]
        )
        self.assertEqual(status, "exact")
        self.assertEqual(header, "SourceFilename")

    def test_fuzzy_match_case_difference(self) -> None:
        status, header = ForensicAnalyzer._match_column_name(
            "sourcefilename", ["SourceFilename", "Path"]
        )
        self.assertEqual(status, "fuzzy")
        self.assertEqual(header, "SourceFilename")

    def test_fuzzy_match_underscore_vs_no_separator(self) -> None:
        status, header = ForensicAnalyzer._match_column_name(
            "Source_Filename", ["SourceFilename", "Path"]
        )
        self.assertEqual(status, "fuzzy")
        self.assertEqual(header, "SourceFilename")

    def test_fuzzy_match_space_vs_underscore(self) -> None:
        status, header = ForensicAnalyzer._match_column_name(
            "Source Filename", ["Source_Filename", "Path"]
        )
        self.assertEqual(status, "fuzzy")
        self.assertEqual(header, "Source_Filename")

    def test_unverifiable_no_match(self) -> None:
        status, header = ForensicAnalyzer._match_column_name(
            "NonExistentColumn", ["SourceFilename", "Path"]
        )
        self.assertEqual(status, "unverifiable")
        self.assertIsNone(header)

    def test_unverifiable_empty_columns(self) -> None:
        status, header = ForensicAnalyzer._match_column_name("Anything", [])
        self.assertEqual(status, "unverifiable")
        self.assertIsNone(header)


class TestValidateCitationsColumns(unittest.TestCase):
    """Tests for column-name citation validation in _validate_citations."""

    def _make_analyzer_with_csv(
        self, tmp_dir: str, headers: list[str], rows: list[list[str]]
    ) -> tuple[ForensicAnalyzer, Path]:
        """Create a ForensicAnalyzer with a CSV file containing the given data."""
        csv_path = Path(tmp_dir) / "artifact.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(row)
        analyzer = ForensicAnalyzer(
            artifact_csv_paths={"test_artifact": csv_path},
        )
        return analyzer, csv_path

    def test_exact_column_match_no_warning(self) -> None:
        with TemporaryDirectory(prefix="aift-col-test-") as tmp_dir:
            analyzer, _ = self._make_analyzer_with_csv(
                tmp_dir, ["Timestamp", "SourceFile"], [["2024-01-01T00:00:00Z", "test.exe"]]
            )
            analysis = "The `SourceFile` column shows suspicious activity."
            warnings = analyzer._validate_citations("test_artifact", analysis)
            # No warnings for exact match columns.
            col_warnings = [w for w in warnings if "column" in w.lower()]
            self.assertEqual(len(col_warnings), 0)

    def test_fuzzy_column_match_produces_warning(self) -> None:
        with TemporaryDirectory(prefix="aift-col-test-") as tmp_dir:
            analyzer, _ = self._make_analyzer_with_csv(
                tmp_dir, ["SourceFilename", "Path"], [["test.exe", "C:\\Windows"]]
            )
            analysis = "The `source_filename` column reveals the origin."
            warnings = analyzer._validate_citations("test_artifact", analysis)
            col_warnings = [w for w in warnings if "fuzzy match" in w.lower()]
            self.assertEqual(len(col_warnings), 1)
            self.assertIn("source_filename", col_warnings[0])
            self.assertIn("SourceFilename", col_warnings[0])

    def test_unverifiable_column_flagged(self) -> None:
        with TemporaryDirectory(prefix="aift-col-test-") as tmp_dir:
            analyzer, _ = self._make_analyzer_with_csv(
                tmp_dir, ["Timestamp", "Path"], [["2024-01-01T00:00:00Z", "C:\\Windows"]]
            )
            analysis = "The `MalwareIndicator` column was not present."
            warnings = analyzer._validate_citations("test_artifact", analysis)
            col_warnings = [w for w in warnings if "unverifiable" in w.lower()]
            self.assertEqual(len(col_warnings), 1)
            self.assertIn("MalwareIndicator", col_warnings[0])

    def test_column_field_keyword_pattern(self) -> None:
        with TemporaryDirectory(prefix="aift-col-test-") as tmp_dir:
            analyzer, _ = self._make_analyzer_with_csv(
                tmp_dir, ["EventID", "Channel"], [["4624", "Security"]]
            )
            analysis = 'The field "FakeColumn" contains interesting data.'
            warnings = analyzer._validate_citations("test_artifact", analysis)
            col_warnings = [w for w in warnings if "unverifiable" in w.lower()]
            self.assertEqual(len(col_warnings), 1)
            self.assertIn("FakeColumn", col_warnings[0])

    def test_analysis_failed_returns_empty(self) -> None:
        with TemporaryDirectory(prefix="aift-col-test-") as tmp_dir:
            analyzer, _ = self._make_analyzer_with_csv(
                tmp_dir, ["Col"], [["val"]]
            )
            warnings = analyzer._validate_citations(
                "test_artifact", "Analysis failed: provider error"
            )
            self.assertEqual(warnings, [])


class TestEstimateTokens(unittest.TestCase):
    """Tests for ForensicAnalyzer._estimate_tokens heuristic."""

    def _make_analyzer(self) -> ForensicAnalyzer:
        """Create a minimal analyzer with tiktoken disabled for heuristic tests."""
        analyzer = ForensicAnalyzer()
        # Ensure heuristic path even if tiktoken is installed.
        analyzer.model_info = {"provider": "anthropic", "model": "test"}
        return analyzer

    def test_empty_string_returns_one(self) -> None:
        analyzer = self._make_analyzer()
        self.assertEqual(analyzer._estimate_tokens(""), 1)

    def test_pure_ascii_roughly_len_div_4(self) -> None:
        analyzer = self._make_analyzer()
        text = "hello world this is a test"
        result = analyzer._estimate_tokens(text)
        naive = len(text) // 4
        # With 10% margin the result should be slightly above naive.
        self.assertGreaterEqual(result, naive)
        # But not wildly different for pure ASCII.
        self.assertLessEqual(result, naive * 2)

    def test_cjk_text_higher_than_naive(self) -> None:
        analyzer = self._make_analyzer()
        cjk_text = "\u4f60\u597d\u4e16\u754c" * 50  # 200 CJK characters
        naive = len(cjk_text) // 4
        result = analyzer._estimate_tokens(cjk_text)
        # Non-ASCII at 1.5 tokens/char + 10% margin should exceed naive len/4.
        self.assertGreater(result, naive)

    def test_mixed_content(self) -> None:
        analyzer = self._make_analyzer()
        mixed = "Hello " + "\u4f60\u597d" * 20 + " world"
        result = analyzer._estimate_tokens(mixed)
        # Should be higher than pure ASCII estimate of same length.
        pure_ascii_estimate = len(mixed) // 4
        self.assertGreater(result, pure_ascii_estimate)

    def test_safety_margin_applied(self) -> None:
        analyzer = self._make_analyzer()
        text = "a" * 400  # Pure ASCII, 400 chars -> 100 raw tokens.
        result = analyzer._estimate_tokens(text)
        raw = 400 / 4
        # 10% margin: expect >= 110.
        self.assertGreaterEqual(result, int(raw * 1.1))


class TestBuildFullDataCsv(unittest.TestCase):
    """Tests for ForensicAnalyzer._build_full_data_csv serialization."""

    def test_serializes_rows_with_row_ref_column(self) -> None:
        analyzer = ForensicAnalyzer()
        rows = [
            {"_row_ref": "1", "ts": "2026-01-15T00:00:00", "name": "alpha"},
            {"_row_ref": "2", "ts": "2026-01-16T00:00:00", "name": "beta"},
        ]
        result = analyzer._build_full_data_csv(rows, ["ts", "name"])
        lines = result.strip().split("\n")
        self.assertEqual(lines[0].strip(), "row_ref,ts,name")
        self.assertEqual(len(lines), 3)
        self.assertIn("alpha", lines[1])
        self.assertIn("beta", lines[2])

    def test_empty_columns_returns_placeholder(self) -> None:
        analyzer = ForensicAnalyzer()
        result = analyzer._build_full_data_csv([{"a": "1"}], [])
        self.assertEqual(result, "No columns available.")

    def test_empty_rows_returns_header_only(self) -> None:
        analyzer = ForensicAnalyzer()
        result = analyzer._build_full_data_csv([], ["ts", "name"])
        self.assertIn("row_ref,ts,name", result)

    def test_missing_column_values_produce_empty_cells(self) -> None:
        analyzer = ForensicAnalyzer()
        rows = [{"_row_ref": "1", "ts": "2026-01-15"}]
        result = analyzer._build_full_data_csv(rows, ["ts", "name"])
        self.assertIn("2026-01-15", result)
        # "name" column should be empty for this row
        lines = result.strip().split("\n")
        self.assertEqual(len(lines[1].split(",")), 3)


class TestValidateCitationsTimestamps(unittest.TestCase):
    """Tests for timestamp and row citation validation in _validate_citations."""

    def _make_analyzer_with_csv(
        self, tmp_dir: str, headers: list[str], rows: list[list[str]]
    ) -> ForensicAnalyzer:
        csv_path = Path(tmp_dir) / "artifact.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(row)
        return ForensicAnalyzer(artifact_csv_paths={"test_artifact": csv_path})

    def test_valid_timestamp_citation_no_warning(self) -> None:
        with TemporaryDirectory(prefix="aift-cite-test-") as tmp_dir:
            analyzer = self._make_analyzer_with_csv(
                tmp_dir,
                ["ts", "value"],
                [["2026-01-15T09:30:00Z", "test"]],
            )
            warnings = analyzer._validate_citations(
                "test_artifact", "At 2026-01-15T09:30:00Z the event occurred."
            )
            ts_warnings = [w for w in warnings if "timestamp" in w.lower()]
            self.assertEqual(len(ts_warnings), 0)

    def test_invalid_timestamp_citation_produces_warning(self) -> None:
        with TemporaryDirectory(prefix="aift-cite-test-") as tmp_dir:
            analyzer = self._make_analyzer_with_csv(
                tmp_dir,
                ["ts", "value"],
                [["2026-01-15T09:30:00Z", "test"]],
            )
            warnings = analyzer._validate_citations(
                "test_artifact", "At 2099-12-31T00:00:00Z the event occurred."
            )
            ts_warnings = [w for w in warnings if "timestamp" in w.lower()]
            self.assertGreaterEqual(len(ts_warnings), 1)

    def test_missing_csv_returns_empty(self) -> None:
        analyzer = ForensicAnalyzer(artifact_csv_paths={"test_artifact": Path("/nonexistent.csv")})
        warnings = analyzer._validate_citations("test_artifact", "Some `Column` cited.")
        self.assertEqual(warnings, [])


class TestCitationValidationUsesAnalysisInputCsv(unittest.TestCase):
    """Tests that _validate_citations uses the analysis-input CSV, not the raw CSV."""

    def _write_csv(self, path: Path, headers: list[str], rows: list[list[str]]) -> None:
        """Write a CSV file with the given headers and rows."""
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(row)

    def test_split_artifact_validates_against_combined_csv(self) -> None:
        """Citation data only in the second split part must be found."""
        with TemporaryDirectory(prefix="aift-split-cite-") as tmp_dir:
            # Part 1 has one timestamp; part 2 has a different one.
            part1 = Path(tmp_dir) / "evtx_part1.csv"
            part2 = Path(tmp_dir) / "evtx_part2.csv"
            self._write_csv(part1, ["ts", "msg"], [["2026-01-01T00:00:00Z", "a"]])
            self._write_csv(part2, ["ts", "msg"], [["2026-06-15T12:00:00Z", "b"]])

            # Build a combined CSV containing both parts.
            combined = Path(tmp_dir) / "evtx_combined.csv"
            self._write_csv(
                combined, ["ts", "msg"],
                [["2026-01-01T00:00:00Z", "a"], ["2026-06-15T12:00:00Z", "b"]],
            )

            # Register the split parts as the original CSVs and the combined
            # as the analysis-input CSV.
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": [part1, part2]},
            )
            analyzer._set_analysis_input_csv_path("evtx", combined)

            # Cite the timestamp from part 2 — should validate successfully.
            analysis = "At 2026-06-15T12:00:00Z a suspicious event occurred."
            warnings = analyzer._validate_citations("evtx", analysis)
            ts_warnings = [w for w in warnings if "timestamp" in w.lower()]
            self.assertEqual(len(ts_warnings), 0, f"Unexpected warnings: {ts_warnings}")

    def test_projected_artifact_validates_against_analysis_input_csv(self) -> None:
        """Citation validation must use the projected/deduped CSV, not the raw one."""
        with TemporaryDirectory(prefix="aift-proj-cite-") as tmp_dir:
            # Raw CSV has column "RawCol" but not "ProjectedCol".
            raw_csv = Path(tmp_dir) / "artifact_raw.csv"
            self._write_csv(raw_csv, ["RawCol"], [["val1"]])

            # Analysis-input CSV has "ProjectedCol" but not "RawCol".
            analysis_csv = Path(tmp_dir) / "artifact_analysis.csv"
            self._write_csv(analysis_csv, ["ProjectedCol"], [["val2"]])

            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"myartifact": raw_csv},
            )
            analyzer._set_analysis_input_csv_path("myartifact", analysis_csv)

            # Cite ProjectedCol — should be found in the analysis-input CSV.
            analysis = "The `ProjectedCol` column reveals important data."
            warnings = analyzer._validate_citations("myartifact", analysis)
            unverifiable = [w for w in warnings if "unverifiable" in w.lower()]
            self.assertEqual(len(unverifiable), 0, f"Unexpected warnings: {unverifiable}")

            # Cite RawCol — should NOT be found (we validate against analysis CSV).
            analysis2 = "The `RawCol` column was checked."
            warnings2 = analyzer._validate_citations("myartifact", analysis2)
            unverifiable2 = [w for w in warnings2 if "unverifiable" in w.lower()]
            self.assertGreaterEqual(len(unverifiable2), 1)

    def test_single_file_artifact_unchanged_behavior(self) -> None:
        """Single-file artifacts without analysis-input override work as before."""
        with TemporaryDirectory(prefix="aift-single-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "artifact.csv"
            self._write_csv(
                csv_path, ["ts", "value"],
                [["2026-03-10T08:00:00Z", "test"]],
            )
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"simple": csv_path},
            )
            # No _set_analysis_input_csv_path — fallback to original.
            analysis = "At 2026-03-10T08:00:00Z the event was logged."
            warnings = analyzer._validate_citations("simple", analysis)
            ts_warnings = [w for w in warnings if "timestamp" in w.lower()]
            self.assertEqual(len(ts_warnings), 0)


###############################################################################
# utils.py — standalone function tests
###############################################################################


class TestStringifyValue(unittest.TestCase):
    """Tests for utils.stringify_value."""

    def test_none_returns_empty(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value(None), "")

    def test_string_stripped(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value("  hello  "), "hello")

    def test_int_converted(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value(42), "42")

    def test_empty_string(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value(""), "")


class TestFormatDatetime(unittest.TestCase):
    """Tests for utils.format_datetime."""

    def test_none_returns_na(self) -> None:
        from app.analyzer.utils import format_datetime
        self.assertEqual(format_datetime(None), "N/A")

    def test_datetime_returns_iso(self) -> None:
        from app.analyzer.utils import format_datetime
        dt = datetime(2026, 1, 15, 12, 0, 0)
        self.assertEqual(format_datetime(dt), "2026-01-15T12:00:00")


class TestNormalizeTableCell(unittest.TestCase):
    """Tests for utils.normalize_table_cell."""

    def test_short_value_unchanged(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        self.assertEqual(normalize_table_cell("hello", 100), "hello")

    def test_long_value_truncated_with_ellipsis(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("a" * 50, 20)
        self.assertTrue(result.endswith("..."))
        self.assertEqual(len(result), 20)

    def test_very_small_limit(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("abcdef", 3)
        self.assertEqual(result, "abc")

    def test_newlines_replaced(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("line1\nline2\rline3", 100)
        self.assertNotIn("\n", result)
        self.assertNotIn("\r", result)

    def test_pipe_escaped(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("a|b", 100)
        self.assertIn(r"\|", result)


class TestSanitizeFilename(unittest.TestCase):
    """Tests for utils.sanitize_filename."""

    def test_clean_name_unchanged(self) -> None:
        from app.analyzer.utils import sanitize_filename
        self.assertEqual(sanitize_filename("runkeys"), "runkeys")

    def test_special_chars_replaced(self) -> None:
        from app.analyzer.utils import sanitize_filename
        result = sanitize_filename("evtx/Security!@#")
        self.assertNotIn("/", result)
        self.assertNotIn("!", result)

    def test_empty_returns_artifact(self) -> None:
        from app.analyzer.utils import sanitize_filename
        self.assertEqual(sanitize_filename(""), "artifact")

    def test_only_special_chars_returns_artifact(self) -> None:
        from app.analyzer.utils import sanitize_filename
        self.assertEqual(sanitize_filename("!!!"), "artifact")


class TestTruncateForPrompt(unittest.TestCase):
    """Tests for utils.truncate_for_prompt."""

    def test_short_string_unchanged(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        self.assertEqual(truncate_for_prompt("hello", 100), "hello")

    def test_long_string_truncated(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        result = truncate_for_prompt("a" * 100, 50)
        self.assertIn("[truncated]", result)
        # The function uses limit - 14 for the prefix, plus " ... [truncated]"
        # which is 14 chars, so the result may be close to but not exceed limit+2.
        self.assertLess(len(result), 60)

    def test_very_small_limit(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        result = truncate_for_prompt("abcdefghij", 5)
        self.assertEqual(result, "abcde")

    def test_none_value(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        result = truncate_for_prompt(None, 100)
        self.assertEqual(result, "")


class TestUniquePreserveOrder(unittest.TestCase):
    """Tests for utils.unique_preserve_order."""

    def test_deduplicates_case_insensitive(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(["Alpha", "alpha", "Beta"])
        self.assertEqual(result, ["Alpha", "Beta"])

    def test_strips_quotes_and_brackets(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(['"hello"', "'world'", "[test]"])
        self.assertEqual(result, ["hello", "world", "test"])

    def test_empty_values_skipped(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(["", "  ", "a"])
        self.assertEqual(result, ["a"])

    def test_trailing_punctuation_stripped(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(["hello.", "world;"])
        self.assertEqual(result, ["hello", "world"])


class TestBuildDatetime(unittest.TestCase):
    """Tests for utils.build_datetime."""

    def test_valid_date(self) -> None:
        from app.analyzer.utils import build_datetime
        result = build_datetime("2026", "1", "15")
        self.assertEqual(result, datetime(2026, 1, 15))

    def test_invalid_date_returns_none(self) -> None:
        from app.analyzer.utils import build_datetime
        result = build_datetime("2026", "13", "1")
        self.assertIsNone(result)

    def test_invalid_day_returns_none(self) -> None:
        from app.analyzer.utils import build_datetime
        result = build_datetime("2026", "2", "30")
        self.assertIsNone(result)


class TestNormalizeDatetime(unittest.TestCase):
    """Tests for utils.normalize_datetime."""

    def test_naive_unchanged(self) -> None:
        from app.analyzer.utils import normalize_datetime
        dt = datetime(2026, 1, 15, 12, 0, 0)
        result = normalize_datetime(dt)
        self.assertEqual(result, dt)
        self.assertIsNone(result.tzinfo)

    def test_aware_converted_to_naive_utc(self) -> None:
        from app.analyzer.utils import normalize_datetime
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = normalize_datetime(dt)
        self.assertEqual(result, datetime(2026, 1, 15, 12, 0, 0))
        self.assertIsNone(result.tzinfo)


class TestParseInt(unittest.TestCase):
    """Tests for utils.parse_int."""

    def test_simple_int(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertEqual(parse_int("42"), 42)

    def test_negative_int(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertEqual(parse_int("-5"), -5)

    def test_embedded_int(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertEqual(parse_int("row 123 here"), 123)

    def test_empty_returns_none(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertIsNone(parse_int(""))

    def test_no_digits_returns_none(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertIsNone(parse_int("abc"))


class TestParseDatetimeValue(unittest.TestCase):
    """Tests for utils.parse_datetime_value."""

    def test_iso_format(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15T12:00:00")
        self.assertEqual(result, datetime(2026, 1, 15, 12, 0, 0))

    def test_iso_with_z(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15T12:00:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result, datetime(2026, 1, 15, 12, 0, 0))

    def test_date_only(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_empty_returns_none(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        self.assertIsNone(parse_datetime_value(""))

    def test_none_returns_none(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        self.assertIsNone(parse_datetime_value(None))

    def test_epoch_seconds(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        # 2026-01-15 00:00:00 UTC = 1768435200
        result = parse_datetime_value("1768435200")
        self.assertIsNotNone(result)

    def test_epoch_millis(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("1768435200000")
        self.assertIsNotNone(result)

    def test_garbage_returns_none(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        self.assertIsNone(parse_datetime_value("not-a-date"))

    def test_epoch_rejected_when_allow_epoch_false(self) -> None:
        """Epoch integers should be rejected when allow_epoch=False."""
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("1768435200", allow_epoch=False)
        self.assertIsNone(result)

    def test_string_date_accepted_when_allow_epoch_false(self) -> None:
        """String-format dates should still parse when allow_epoch=False."""
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15T12:00:00", allow_epoch=False)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)


class TestLooksLikeTimestampColumn(unittest.TestCase):
    """Tests for utils.looks_like_timestamp_column."""

    def test_timestamp_hint(self) -> None:
        from app.analyzer.utils import looks_like_timestamp_column
        self.assertTrue(looks_like_timestamp_column("ts"))
        self.assertTrue(looks_like_timestamp_column("Timestamp"))
        self.assertTrue(looks_like_timestamp_column("created_date"))
        self.assertTrue(looks_like_timestamp_column("LastModified"))

    def test_non_timestamp(self) -> None:
        from app.analyzer.utils import looks_like_timestamp_column
        self.assertFalse(looks_like_timestamp_column("name"))
        self.assertFalse(looks_like_timestamp_column("EventID"))


class TestExtractRowDatetime(unittest.TestCase):
    """Tests for utils.extract_row_datetime."""

    def test_finds_timestamp_column(self) -> None:
        from app.analyzer.utils import extract_row_datetime
        row = {"ts": "2026-01-15T12:00:00", "name": "test"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_returns_none_for_no_timestamps(self) -> None:
        from app.analyzer.utils import extract_row_datetime
        row = {"name": "test", "value": "abc"}
        result = extract_row_datetime(row)
        self.assertIsNone(result)

    def test_with_explicit_columns(self) -> None:
        from app.analyzer.utils import extract_row_datetime
        row = {"ts": "2026-01-15T12:00:00", "name": "test"}
        result = extract_row_datetime(row, columns=["ts", "name"])
        self.assertIsNotNone(result)

    def test_numeric_id_without_timestamp_columns_returns_none(self) -> None:
        """Numeric IDs in non-timestamp columns must not be mistaken for epochs."""
        from app.analyzer.utils import extract_row_datetime
        row = {"record_id": "1768435200", "name": "test", "count": "42"}
        result = extract_row_datetime(row)
        self.assertIsNone(result)

    def test_numeric_id_ignored_when_timestamp_column_present(self) -> None:
        """When a timestamp column exists, numeric IDs in other columns are irrelevant."""
        from app.analyzer.utils import extract_row_datetime
        row = {"ts": "2026-01-15T12:00:00", "record_id": "9999999999"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_epoch_in_timestamp_column_still_works(self) -> None:
        """Epoch integers in a timestamp-named column should still parse."""
        from app.analyzer.utils import extract_row_datetime
        # 1768435200 = 2026-01-15 00:00:00 UTC
        row = {"timestamp": "1768435200", "name": "test"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_string_date_in_non_timestamp_column_still_works(self) -> None:
        """String-format dates in non-timestamp columns should still parse."""
        from app.analyzer.utils import extract_row_datetime
        row = {"event_info": "2026-01-15T12:00:00", "id": "42"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_all_numeric_non_timestamp_columns_returns_none(self) -> None:
        """Rows with only numeric values and no timestamp columns produce None."""
        from app.analyzer.utils import extract_row_datetime
        row = {"id": "1000000001", "size": "2000000000", "count": "3000000000"}
        result = extract_row_datetime(row)
        self.assertIsNone(result)


class TestTimeRangeForRows(unittest.TestCase):
    """Tests for utils.time_range_for_rows."""

    def test_computes_range(self) -> None:
        from app.analyzer.utils import time_range_for_rows
        rows = [
            {"ts": "2026-01-15T10:00:00"},
            {"ts": "2026-01-17T10:00:00"},
            {"ts": "2026-01-16T10:00:00"},
        ]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNotNone(min_t)
        self.assertIsNotNone(max_t)
        self.assertEqual(min_t.day, 15)
        self.assertEqual(max_t.day, 17)

    def test_empty_rows(self) -> None:
        from app.analyzer.utils import time_range_for_rows
        min_t, max_t = time_range_for_rows([])
        self.assertIsNone(min_t)
        self.assertIsNone(max_t)

    def test_no_timestamps(self) -> None:
        from app.analyzer.utils import time_range_for_rows
        rows = [{"name": "test"}, {"name": "test2"}]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNone(min_t)
        self.assertIsNone(max_t)

    def test_numeric_ids_not_mistaken_for_time_range(self) -> None:
        """Rows with only numeric IDs in non-timestamp columns produce no range."""
        from app.analyzer.utils import time_range_for_rows
        rows = [
            {"id": "1000000001", "size": "2000000000"},
            {"id": "1000000002", "size": "2000000001"},
        ]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNone(min_t)
        self.assertIsNone(max_t)

    def test_real_timestamps_still_produce_correct_range(self) -> None:
        """Genuine timestamp columns still yield correct time ranges."""
        from app.analyzer.utils import time_range_for_rows
        rows = [
            {"created_date": "2026-01-10T08:00:00", "id": "1000000001"},
            {"created_date": "2026-01-20T08:00:00", "id": "1000000002"},
        ]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNotNone(min_t)
        self.assertIsNotNone(max_t)
        self.assertEqual(min_t.day, 10)
        self.assertEqual(max_t.day, 20)


class TestNormalizeArtifactKey(unittest.TestCase):
    """Tests for utils.normalize_artifact_key."""

    def test_known_normalizations(self) -> None:
        from app.analyzer.utils import normalize_artifact_key
        self.assertEqual(normalize_artifact_key("mft"), "mft")
        self.assertEqual(normalize_artifact_key("MFT"), "mft")
        self.assertEqual(normalize_artifact_key("evtx_Security"), "evtx")
        self.assertEqual(normalize_artifact_key("shimcache_data"), "shimcache")
        self.assertEqual(normalize_artifact_key("amcache.applications"), "amcache")
        self.assertEqual(normalize_artifact_key("prefetch_data"), "prefetch")
        self.assertEqual(normalize_artifact_key("services_list"), "services")
        self.assertEqual(normalize_artifact_key("tasks_scheduled"), "tasks")
        self.assertEqual(normalize_artifact_key("userassist_data"), "userassist")
        self.assertEqual(normalize_artifact_key("runkeys_data"), "runkeys")

    def test_unknown_key_lowered(self) -> None:
        from app.analyzer.utils import normalize_artifact_key
        self.assertEqual(normalize_artifact_key("CustomArtifact"), "customartifact")


class TestExtractUrlHost(unittest.TestCase):
    """Tests for utils.extract_url_host."""

    def test_full_url(self) -> None:
        from app.analyzer.utils import extract_url_host
        self.assertEqual(extract_url_host("https://evil.example.com/path"), "evil.example.com")

    def test_url_with_port(self) -> None:
        from app.analyzer.utils import extract_url_host
        self.assertEqual(extract_url_host("http://host.com:8080/path"), "host.com")

    def test_bare_host(self) -> None:
        from app.analyzer.utils import extract_url_host
        self.assertEqual(extract_url_host("example.com/path"), "example.com")


class TestNormalizeCsvRow(unittest.TestCase):
    """Tests for utils.normalize_csv_row."""

    def test_normalizes_values(self) -> None:
        from app.analyzer.utils import normalize_csv_row
        row = {"col1": "  hello  ", "col2": None, "col3": 42}
        result = normalize_csv_row(row, ["col1", "col2"])
        self.assertEqual(result["col1"], "hello")
        self.assertEqual(result["col2"], "")

    def test_extra_fields(self) -> None:
        from app.analyzer.utils import normalize_csv_row
        row = {"col1": "val1", None: ["extra1", "extra2"]}
        result = normalize_csv_row(row, ["col1"])
        self.assertIn("__extra__", result)
        self.assertIn("extra1", result["__extra__"])


class TestCoerceProjectionColumns(unittest.TestCase):
    """Tests for utils.coerce_projection_columns."""

    def test_string_split(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns("ts, name, command")
        self.assertEqual(result, ["ts", "name", "command"])

    def test_list_input(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns(["ts", "name"])
        self.assertEqual(result, ["ts", "name"])

    def test_deduplicates(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns(["ts", "name", "ts"])
        self.assertEqual(result, ["ts", "name"])

    def test_non_string_non_list_returns_empty(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns(42)
        self.assertEqual(result, [])


class TestEmitAnalysisProgress(unittest.TestCase):
    """Tests for utils.emit_analysis_progress."""

    def test_three_arg_callback(self) -> None:
        from app.analyzer.utils import emit_analysis_progress
        calls = []
        def cb(key, status, payload):
            calls.append((key, status, payload))
        emit_analysis_progress(cb, "art1", "started", {"msg": "hi"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "art1")

    def test_single_arg_fallback(self) -> None:
        from app.analyzer.utils import emit_analysis_progress
        calls = []
        def cb(payload):
            calls.append(payload)
        emit_analysis_progress(cb, "art1", "started", {"msg": "hi"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["artifact_key"], "art1")

    def test_broken_callback_does_not_raise(self) -> None:
        from app.analyzer.utils import emit_analysis_progress
        def cb(*args, **kwargs):
            raise RuntimeError("broken")
        # Should not raise
        emit_analysis_progress(cb, "art1", "started", {"msg": "hi"})


class TestReadIntSetting(unittest.TestCase):
    """Tests for utils.read_int_setting."""

    def test_default_used(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({}, "key", 10), 10)

    def test_value_parsed(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": "42"}, "key", 10), 42)

    def test_minimum_clamping(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": -5}, "key", 10, minimum=1), 1)

    def test_maximum_clamping(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": 100}, "key", 10, maximum=50), 50)

    def test_invalid_value_uses_default(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": "abc"}, "key", 10), 10)


class TestReadBoolSetting(unittest.TestCase):
    """Tests for utils.read_bool_setting."""

    def test_bool_value(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({"key": True}, "key", False))
        self.assertFalse(read_bool_setting({"key": False}, "key", True))

    def test_string_true_variants(self) -> None:
        from app.analyzer.utils import read_bool_setting
        for val in ("true", "1", "yes", "on", "True", "YES"):
            self.assertTrue(read_bool_setting({"key": val}, "key", False))

    def test_string_false_variants(self) -> None:
        from app.analyzer.utils import read_bool_setting
        for val in ("false", "0", "no", "off"):
            self.assertFalse(read_bool_setting({"key": val}, "key", True))

    def test_int_value(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({"key": 1}, "key", False))
        self.assertFalse(read_bool_setting({"key": 0}, "key", True))

    def test_default_on_missing(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({}, "key", True))

    def test_non_parseable_uses_default(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({"key": "maybe"}, "key", True))


class TestReadPathSetting(unittest.TestCase):
    """Tests for utils.read_path_setting."""

    def test_string_value(self) -> None:
        from app.analyzer.utils import read_path_setting
        self.assertEqual(read_path_setting({"key": "/some/path"}, "key", "/default"), "/some/path")

    def test_empty_string_uses_default(self) -> None:
        from app.analyzer.utils import read_path_setting
        self.assertEqual(read_path_setting({"key": ""}, "key", "/default"), "/default")

    def test_missing_uses_default(self) -> None:
        from app.analyzer.utils import read_path_setting
        self.assertEqual(read_path_setting({}, "key", "/default"), "/default")

    def test_path_object(self) -> None:
        from app.analyzer.utils import read_path_setting
        result = read_path_setting({"key": Path("/some/path")}, "key", "/default")
        # On Windows, Path("/some/path") becomes "\\some\\path", so compare Path objects.
        self.assertEqual(Path(result), Path("/some/path"))


class TestIsDeupSafeIdentifierColumn(unittest.TestCase):
    """Tests for utils.is_dedup_safe_identifier_column."""

    def test_safe_columns(self) -> None:
        from app.analyzer.utils import is_dedup_safe_identifier_column
        self.assertTrue(is_dedup_safe_identifier_column("record_id"))
        self.assertTrue(is_dedup_safe_identifier_column("RecordID"))
        self.assertTrue(is_dedup_safe_identifier_column("entry_id"))
        self.assertTrue(is_dedup_safe_identifier_column("index"))
        self.assertTrue(is_dedup_safe_identifier_column("sequence_number"))

    def test_unsafe_columns(self) -> None:
        from app.analyzer.utils import is_dedup_safe_identifier_column
        self.assertFalse(is_dedup_safe_identifier_column("EventID"))
        self.assertFalse(is_dedup_safe_identifier_column("ProcessID"))
        self.assertFalse(is_dedup_safe_identifier_column("name"))


class TestEstimateTokensStandalone(unittest.TestCase):
    """Tests for utils.estimate_tokens as standalone function."""

    def test_empty_returns_one(self) -> None:
        from app.analyzer.utils import estimate_tokens
        self.assertEqual(estimate_tokens(""), 1)

    def test_heuristic_ascii(self) -> None:
        from app.analyzer.utils import estimate_tokens
        text = "a" * 400
        result = estimate_tokens(text, model_info={"provider": "anthropic", "model": "claude"})
        self.assertGreaterEqual(result, 100)

    def test_none_model_info(self) -> None:
        from app.analyzer.utils import estimate_tokens
        result = estimate_tokens("hello world")
        self.assertGreaterEqual(result, 1)


###############################################################################
# chunking.py — standalone function tests
###############################################################################


class TestSplitCsvIntoChunks(unittest.TestCase):
    """Tests for chunking.split_csv_into_chunks."""

    def test_small_csv_returns_single_chunk(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = "header\nrow1\nrow2"
        result = split_csv_into_chunks(csv_text, max_chars=1000)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], csv_text)

    def test_splits_at_row_boundaries(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        header = "col1,col2"
        rows = [f"val{i},data{i}" for i in range(100)]
        csv_text = header + "\n" + "\n".join(rows)
        result = split_csv_into_chunks(csv_text, max_chars=200)
        self.assertGreater(len(result), 1)
        for chunk in result:
            self.assertTrue(chunk.startswith(header))

    def test_zero_max_chars_returns_single_chunk(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = "header\nrow1"
        result = split_csv_into_chunks(csv_text, max_chars=0)
        self.assertEqual(len(result), 1)

    def test_header_only_csv(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = "col1,col2"
        result = split_csv_into_chunks(csv_text, max_chars=5)
        self.assertEqual(len(result), 1)

    def test_empty_string(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        result = split_csv_into_chunks("", max_chars=100)
        self.assertEqual(len(result), 1)


class TestSplitCsvAndSuffix(unittest.TestCase):
    """Tests for chunking.split_csv_and_suffix."""

    def test_plain_csv(self) -> None:
        from app.analyzer.chunking import split_csv_and_suffix
        csv_data, suffix = split_csv_and_suffix("col1,col2\nval1,val2")
        self.assertEqual(csv_data, "col1,col2\nval1,val2")
        self.assertEqual(suffix, "")

    def test_with_trailing_fence(self) -> None:
        from app.analyzer.chunking import split_csv_and_suffix
        text = "col1,col2\nval1,val2\n```"
        csv_data, suffix = split_csv_and_suffix(text)
        self.assertEqual(csv_data, "col1,col2\nval1,val2")
        self.assertIn("```", suffix)

    def test_with_final_context_reminder(self) -> None:
        from app.analyzer.chunking import split_csv_and_suffix
        text = "col1,col2\nval1,val2\n\n## Final Context Reminder\nDo not ignore."
        csv_data, suffix = split_csv_and_suffix(text)
        self.assertEqual(csv_data, "col1,col2\nval1,val2")
        self.assertIn("Final Context Reminder", suffix)


class TestBuildMergePrompt(unittest.TestCase):
    """Tests for chunking._build_merge_prompt."""

    def test_fills_template(self) -> None:
        from app.analyzer.chunking import _build_merge_prompt
        template = "Chunks: {{chunk_count}}\nContext: {{investigation_context}}\nArtifact: {{artifact_name}} ({{artifact_key}})\n{{per_chunk_findings}}"
        result = _build_merge_prompt(
            findings_text="finding1\nfinding2",
            batch_count=3,
            artifact_key="evtx",
            artifact_name="Event Logs",
            investigation_context="Check for lateral movement.",
            chunk_merge_prompt_template=template,
        )
        self.assertIn("Chunks: 3", result)
        self.assertIn("Context: Check for lateral movement.", result)
        self.assertIn("Artifact: Event Logs (evtx)", result)
        self.assertIn("finding1", result)

    def test_empty_context(self) -> None:
        from app.analyzer.chunking import _build_merge_prompt
        template = "{{investigation_context}}"
        result = _build_merge_prompt(
            findings_text="f", batch_count=1, artifact_key="k",
            artifact_name="n", investigation_context="",
            chunk_merge_prompt_template=template,
        )
        self.assertIn("No investigation context provided.", result)


class TestAnalyzeArtifactChunked(unittest.TestCase):
    """Tests for chunking.analyze_artifact_chunked."""

    def test_no_csv_marker_calls_provider_directly(self) -> None:
        from app.analyzer.chunking import analyze_artifact_chunked
        mock_provider = FakeProvider(responses=["direct-response"])
        result = analyze_artifact_chunked(
            artifact_prompt="No CSV section here",
            artifact_key="test",
            artifact_name="Test",
            investigation_context="context",
            model="model",
            system_prompt="system",
            ai_response_max_tokens=1000,
            chunk_csv_budget=5000,
            chunk_merge_prompt_template="{{per_chunk_findings}}",
            max_merge_rounds=5,
            call_ai_with_retry_fn=lambda fn: fn(),
            ai_provider=mock_provider,
        )
        self.assertEqual(result, "direct-response")

    def test_small_csv_calls_provider_directly(self) -> None:
        from app.analyzer.chunking import analyze_artifact_chunked
        prompt = "## Full Data (CSV)\ncol1,col2\nval1,val2"
        mock_provider = FakeProvider(responses=["single-response"])
        result = analyze_artifact_chunked(
            artifact_prompt=prompt,
            artifact_key="test",
            artifact_name="Test",
            investigation_context="context",
            model="model",
            system_prompt="system",
            ai_response_max_tokens=1000,
            chunk_csv_budget=50000,
            chunk_merge_prompt_template="{{per_chunk_findings}}",
            max_merge_rounds=5,
            call_ai_with_retry_fn=lambda fn: fn(),
            ai_provider=mock_provider,
        )
        self.assertEqual(result, "single-response")


###############################################################################
# citations.py — standalone function tests
###############################################################################


class TestTimestampLookupKeys(unittest.TestCase):
    """Tests for citations.timestamp_lookup_keys."""

    def test_empty_string(self) -> None:
        from app.analyzer.citations import timestamp_lookup_keys
        self.assertEqual(timestamp_lookup_keys(""), set())

    def test_iso_timestamp_generates_multiple_keys(self) -> None:
        from app.analyzer.citations import timestamp_lookup_keys
        keys = timestamp_lookup_keys("2026-01-15T12:00:00Z")
        self.assertGreater(len(keys), 1)
        self.assertIn("2026-01-15T12:00:00Z", keys)

    def test_timestamp_with_offset(self) -> None:
        from app.analyzer.citations import timestamp_lookup_keys
        keys = timestamp_lookup_keys("2026-01-15T12:00:00+00:00")
        self.assertGreater(len(keys), 1)


class TestTimestampFoundInCsv(unittest.TestCase):
    """Tests for citations.timestamp_found_in_csv."""

    def test_empty_lookup(self) -> None:
        from app.analyzer.citations import timestamp_found_in_csv
        self.assertFalse(timestamp_found_in_csv("2026-01-15T12:00:00Z", set()))

    def test_found(self) -> None:
        from app.analyzer.citations import timestamp_found_in_csv, timestamp_lookup_keys
        lookup = timestamp_lookup_keys("2026-01-15T12:00:00Z")
        self.assertTrue(timestamp_found_in_csv("2026-01-15T12:00:00Z", lookup))

    def test_not_found(self) -> None:
        from app.analyzer.citations import timestamp_found_in_csv, timestamp_lookup_keys
        lookup = timestamp_lookup_keys("2026-01-15T12:00:00Z")
        self.assertFalse(timestamp_found_in_csv("2099-12-31T00:00:00Z", lookup))


class TestMatchColumnNameStandalone(unittest.TestCase):
    """Tests for citations.match_column_name as standalone function."""

    def test_exact(self) -> None:
        from app.analyzer.citations import match_column_name
        status, header = match_column_name("Path", ["ts", "Path"])
        self.assertEqual(status, "exact")
        self.assertEqual(header, "Path")

    def test_fuzzy(self) -> None:
        from app.analyzer.citations import match_column_name
        status, header = match_column_name("source_file", ["SourceFile"])
        self.assertEqual(status, "fuzzy")
        self.assertEqual(header, "SourceFile")

    def test_unverifiable(self) -> None:
        from app.analyzer.citations import match_column_name
        status, header = match_column_name("NonExistent", ["ts", "Path"])
        self.assertEqual(status, "unverifiable")
        self.assertIsNone(header)


class TestValidateCitationsStandalone(unittest.TestCase):
    """Tests for citations.validate_citations as standalone function."""

    def test_failed_analysis_returns_empty(self) -> None:
        from app.analyzer.citations import validate_citations
        result = validate_citations("art", "Analysis failed: error", Path("/fake.csv"), 20)
        self.assertEqual(result, [])

    def test_no_citations_returns_empty(self) -> None:
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "test.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["ts", "name"])
                writer.writerow(["2026-01-15T12:00:00Z", "test"])
            result = validate_citations("art", "No specific citations here", csv_path, 20)
        self.assertEqual(result, [])

    def test_invalid_timestamp_produces_warning(self) -> None:
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "test.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["ts", "name"])
                writer.writerow(["2026-01-15T12:00:00Z", "test"])
            result = validate_citations("art", "At 2099-12-31T00:00:00Z event.", csv_path, 20)
        ts_warnings = [w for w in result if "timestamp" in w.lower()]
        self.assertGreaterEqual(len(ts_warnings), 1)

    def test_invalid_row_ref_produces_warning(self) -> None:
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "test.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["ts", "name"])
                writer.writerow(["2026-01-15T12:00:00Z", "test"])
            result = validate_citations("art", "See row 999 for details.", csv_path, 20)
        row_warnings = [w for w in result if "row" in w.lower()]
        self.assertGreaterEqual(len(row_warnings), 1)

    def test_missing_csv_returns_empty(self) -> None:
        from app.analyzer.citations import validate_citations
        result = validate_citations("art", "At 2026-01-15T12:00:00Z event.", Path("/no/exist.csv"), 20)
        self.assertEqual(result, [])

    def test_audit_log_called_on_warnings(self) -> None:
        from app.analyzer.citations import validate_citations
        audit_calls = []
        def audit_fn(action, details):
            audit_calls.append((action, details))
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "test.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["ts", "name"])
                writer.writerow(["2026-01-15T12:00:00Z", "test"])
            validate_citations("art", "At 2099-12-31T00:00:00Z event.", csv_path, 20, audit_log_fn=audit_fn)
        self.assertGreater(len(audit_calls), 0)
        self.assertEqual(audit_calls[0][0], "citation_validation")


class TestCitationRowRefAfterFiltering(unittest.TestCase):
    """Regression tests: row_ref differs from physical row after filtering/dedup."""

    def test_valid_row_ref_after_filtering(self) -> None:
        """Row refs 3 and 5 survive filtering; physical rows are 1 and 2."""
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "filtered.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["row_ref", "ts", "name"])
                # Physical row 1, but row_ref=3
                writer.writerow(["3", "2026-01-15T09:00:00Z", "alpha"])
                # Physical row 2, but row_ref=5
                writer.writerow(["5", "2026-01-15T10:00:00Z", "beta"])
            # AI cites row 5 — should be valid via row_ref column
            warnings = validate_citations("art", "See row 5 for details.", csv_path, 20)
            row_warnings = [w for w in warnings if "row" in w.lower()]
            self.assertEqual(len(row_warnings), 0, f"Unexpected warnings: {row_warnings}")

    def test_invalid_row_ref_after_filtering(self) -> None:
        """Row ref 2 was filtered out; citing it should produce a warning."""
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "filtered.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["row_ref", "ts", "name"])
                writer.writerow(["3", "2026-01-15T09:00:00Z", "alpha"])
                writer.writerow(["5", "2026-01-15T10:00:00Z", "beta"])
            # AI cites row 2 — was filtered out, should warn
            warnings = validate_citations("art", "See row 2 for details.", csv_path, 20)
            row_warnings = [w for w in warnings if "row" in w.lower()]
            self.assertGreaterEqual(len(row_warnings), 1)

    def test_physical_row_number_invalid_when_row_ref_present(self) -> None:
        """Physical row 1 exists but row_ref=3; citing row 1 should warn."""
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "filtered.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["row_ref", "ts", "name"])
                writer.writerow(["3", "2026-01-15T09:00:00Z", "alpha"])
            # AI cites row 1 (physical row) but row_ref is 3
            warnings = validate_citations("art", "See row 1 for details.", csv_path, 20)
            row_warnings = [w for w in warnings if "row" in w.lower()]
            self.assertGreaterEqual(len(row_warnings), 1)

    def test_row_ref_after_deduplication(self) -> None:
        """After dedup, row_refs are non-contiguous; validation uses them."""
        from app.analyzer.citations import validate_citations
        with TemporaryDirectory(prefix="aift-cite-") as tmp_dir:
            csv_path = Path(tmp_dir) / "deduped.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["row_ref", "ts", "name"])
                writer.writerow(["1", "2026-01-15T09:00:00Z", "alpha"])
                writer.writerow(["4", "2026-01-15T10:00:00Z", "beta"])
                writer.writerow(["7", "2026-01-15T11:00:00Z", "gamma"])
            # Row refs 1, 4, 7 are valid; row 2 is not
            w1 = validate_citations("art", "See row 4 for details.", csv_path, 20)
            self.assertEqual([w for w in w1 if "row" in w.lower()], [])
            w2 = validate_citations("art", "See row 2 for details.", csv_path, 20)
            self.assertGreaterEqual(len([w for w in w2 if "row" in w.lower()]), 1)

    def test_write_analysis_csv_includes_row_ref(self) -> None:
        """write_analysis_input_csv preserves _row_ref as row_ref column."""
        from app.analyzer.data_prep import write_analysis_input_csv
        with TemporaryDirectory(prefix="aift-prep-") as tmp_dir:
            source = Path(tmp_dir) / "source.csv"
            source.write_text("ts,name\na,b\n", encoding="utf-8")
            rows = [
                {"_row_ref": "3", "ts": "2026-01-15", "name": "alpha"},
                {"_row_ref": "7", "ts": "2026-01-16", "name": "beta"},
            ]
            out_path = write_analysis_input_csv(source, rows, ["ts", "name"], case_dir=Path(tmp_dir))
            content = out_path.read_text(encoding="utf-8")
            lines = content.strip().split("\n")
            self.assertTrue(lines[0].startswith("row_ref,"), f"Header: {lines[0]}")
            self.assertIn("3,", lines[1])
            self.assertIn("7,", lines[2])


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


###############################################################################
# data_prep.py — standalone function tests
###############################################################################


class TestExtractDatesFromContext(unittest.TestCase):
    """Tests for data_prep.extract_dates_from_context."""

    def test_empty_text(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        self.assertEqual(extract_dates_from_context(""), [])

    def test_iso_date(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        result = extract_dates_from_context("Incident on 2026-03-15.")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].date().isoformat(), "2026-03-15")

    def test_dmy_dash(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        result = extract_dates_from_context("Date: 15-03-2026")
        self.assertEqual(len(result), 1)

    def test_dmy_slash(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        result = extract_dates_from_context("Date: 15/03/2026")
        self.assertEqual(len(result), 1)

    def test_textual_date(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        result = extract_dates_from_context("Event on March 15, 2026")
        self.assertEqual(len(result), 1)

    def test_textual_range(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        result = extract_dates_from_context("Window is March 10-15, 2026")
        self.assertEqual(len(result), 2)

    def test_deduplicates(self) -> None:
        from app.analyzer.data_prep import extract_dates_from_context
        result = extract_dates_from_context("2026-01-15 and 2026-01-15")
        self.assertEqual(len(result), 1)


class TestCounterNormalize(unittest.TestCase):
    """Tests for data_prep.counter_normalize."""

    def test_low_signal_returns_empty(self) -> None:
        from app.analyzer.data_prep import counter_normalize
        self.assertEqual(counter_normalize("none"), "")
        self.assertEqual(counter_normalize("N/A"), "")
        self.assertEqual(counter_normalize(""), "")

    def test_normal_value_returned(self) -> None:
        from app.analyzer.data_prep import counter_normalize
        self.assertNotEqual(counter_normalize("cmd.exe"), "")


class TestSelectAiColumns(unittest.TestCase):
    """Tests for data_prep.select_ai_columns."""

    def test_no_projection_returns_all(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        cols, applied = select_ai_columns("runkeys", ["ts", "name", "cmd"], {})
        self.assertEqual(cols, ["ts", "name", "cmd"])
        self.assertFalse(applied)

    def test_projection_applied(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        projections = {"runkeys": ("ts", "name")}
        cols, applied = select_ai_columns("runkeys", ["ts", "name", "cmd"], projections)
        self.assertEqual(cols, ["ts", "name"])
        self.assertTrue(applied)

    def test_missing_columns_logged(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        audit_calls = []
        def audit_fn(action, details):
            audit_calls.append((action, details))
        projections = {"runkeys": ("ts", "nonexistent")}
        cols, applied = select_ai_columns("runkeys", ["ts", "name"], projections, audit_log_fn=audit_fn)
        self.assertEqual(cols, ["ts"])
        self.assertTrue(applied)
        self.assertGreater(len(audit_calls), 0)

    def test_all_columns_missing_returns_all(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        projections = {"runkeys": ("x", "y")}
        cols, applied = select_ai_columns("runkeys", ["ts", "name"], projections)
        self.assertEqual(cols, ["ts", "name"])
        self.assertFalse(applied)


class TestProjectRowsForAnalysis(unittest.TestCase):
    """Tests for data_prep.project_rows_for_analysis."""

    def test_projects_columns(self) -> None:
        from app.analyzer.data_prep import project_rows_for_analysis
        rows = [{"ts": "2026-01-15", "name": "a", "extra": "x", "_row_ref": "1"}]
        result = project_rows_for_analysis(rows, ["ts", "name"])
        self.assertEqual(len(result), 1)
        self.assertIn("ts", result[0])
        self.assertIn("name", result[0])
        self.assertNotIn("extra", result[0])
        self.assertEqual(result[0]["_row_ref"], "1")


class TestDeduplicateRowsForAnalysis(unittest.TestCase):
    """Tests for data_prep.deduplicate_rows_for_analysis standalone."""

    def test_empty_rows(self) -> None:
        from app.analyzer.data_prep import deduplicate_rows_for_analysis
        kept, cols, removed, annotated, variants = deduplicate_rows_for_analysis([], [])
        self.assertEqual(kept, [])
        self.assertEqual(removed, 0)

    def test_no_variant_columns(self) -> None:
        from app.analyzer.data_prep import deduplicate_rows_for_analysis
        rows = [{"name": "a"}, {"name": "b"}]
        kept, cols, removed, annotated, variants = deduplicate_rows_for_analysis(rows, ["name"])
        self.assertEqual(len(kept), 2)
        self.assertEqual(removed, 0)
        self.assertEqual(variants, [])


class TestBuildFullDataCsvStandalone(unittest.TestCase):
    """Tests for data_prep.build_full_data_csv standalone."""

    def test_no_columns(self) -> None:
        from app.analyzer.data_prep import build_full_data_csv
        result = build_full_data_csv([{"a": "1"}], [])
        self.assertEqual(result, "No columns available.")

    def test_serializes(self) -> None:
        from app.analyzer.data_prep import build_full_data_csv
        rows = [{"_row_ref": "1", "ts": "2026-01-15", "name": "test"}]
        result = build_full_data_csv(rows, ["ts", "name"])
        self.assertIn("row_ref,ts,name", result)
        self.assertIn("test", result)


class TestResolveAnalysisInputOutputDir(unittest.TestCase):
    """Tests for data_prep.resolve_analysis_input_output_dir."""

    def test_with_case_dir(self) -> None:
        from app.analyzer.data_prep import resolve_analysis_input_output_dir
        result = resolve_analysis_input_output_dir(Path("/case"), Path("/case/parsed/art.csv"))
        self.assertEqual(result, Path("/case/parsed_deduplicated"))

    def test_without_case_dir_parsed_parent(self) -> None:
        from app.analyzer.data_prep import resolve_analysis_input_output_dir
        result = resolve_analysis_input_output_dir(None, Path("/some/parsed/art.csv"))
        self.assertEqual(result, Path("/some/parsed_deduplicated"))

    def test_without_case_dir_non_parsed(self) -> None:
        from app.analyzer.data_prep import resolve_analysis_input_output_dir
        result = resolve_analysis_input_output_dir(None, Path("/some/other/art.csv"))
        self.assertEqual(result, Path("/some/other/parsed_deduplicated"))


class TestWriteAnalysisInputCsv(unittest.TestCase):
    """Tests for data_prep.write_analysis_input_csv."""

    def test_writes_csv(self) -> None:
        from app.analyzer.data_prep import write_analysis_input_csv
        with TemporaryDirectory(prefix="aift-write-") as tmp_dir:
            source = Path(tmp_dir) / "parsed" / "art.csv"
            source.parent.mkdir(parents=True)
            source.write_text("ts,name\n2026-01-15,test\n", encoding="utf-8")
            rows = [{"ts": "2026-01-15", "name": "test"}]
            result = write_analysis_input_csv(source, rows, ["ts", "name"])
            self.assertTrue(result.exists())
            content = result.read_text(encoding="utf-8")
            self.assertIn("ts,name", content)
            self.assertIn("test", content)


class TestBuildArtifactCsvAttachment(unittest.TestCase):
    """Tests for data_prep.build_artifact_csv_attachment."""

    def test_basic(self) -> None:
        from app.analyzer.data_prep import build_artifact_csv_attachment
        csv_path = Path("/path/to/file.csv")
        result = build_artifact_csv_attachment("runkeys", csv_path)
        self.assertEqual(result["path"], str(csv_path))
        self.assertEqual(result["mime_type"], "text/csv")
        self.assertIn("runkeys", result["name"])


class TestResolveAnalysisInstructions(unittest.TestCase):
    """Tests for data_prep._resolve_analysis_instructions."""

    def test_instruction_from_prompts(self) -> None:
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="evtx_Security",
            artifact_metadata={},
            artifact_instruction_prompts={"evtx": "EVTX INSTRUCTIONS"},
        )
        self.assertEqual(result, "EVTX INSTRUCTIONS")

    def test_instruction_from_metadata(self) -> None:
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="custom",
            artifact_metadata={"analysis_instructions": "Custom guidance"},
            artifact_instruction_prompts={},
        )
        self.assertEqual(result, "Custom guidance")

    def test_default_message(self) -> None:
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="custom",
            artifact_metadata={},
            artifact_instruction_prompts={},
        )
        self.assertIn("No specific analysis instructions", result)


###############################################################################
# constants.py — UnavailableProvider tests
###############################################################################


class TestUnavailableProvider(unittest.TestCase):
    """Tests for constants.UnavailableProvider."""

    def test_analyze_raises(self) -> None:
        from app.analyzer.constants import UnavailableProvider
        provider = UnavailableProvider("Test error")
        with self.assertRaises(AIProviderError):
            provider.analyze("sys", "user")

    def test_get_model_info(self) -> None:
        from app.analyzer.constants import UnavailableProvider
        provider = UnavailableProvider("err")
        info = provider.get_model_info()
        self.assertEqual(info["provider"], "unavailable")
        self.assertEqual(info["model"], "unavailable")


###############################################################################
# core.py — ForensicAnalyzer method tests
###############################################################################


class TestCallAiWithRetry(unittest.TestCase):
    """Tests for ForensicAnalyzer._call_ai_with_retry."""

    def test_success_on_first_try(self) -> None:
        fake_provider = FakeProvider(responses=["ok"])
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        result = analyzer._call_ai_with_retry(lambda: "success")
        self.assertEqual(result, "success")

    def test_raises_ai_provider_error_immediately(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        with self.assertRaises(AIProviderError):
            analyzer._call_ai_with_retry(lambda: (_ for _ in ()).throw(AIProviderError("permanent")))

    @patch("app.analyzer.core.sleep")
    def test_retries_on_transient_error(self, mock_sleep) -> None:
        call_count = 0
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("transient")
            return "success"
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        result = analyzer._call_ai_with_retry(flaky)
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 3)

    @patch("app.analyzer.core.sleep")
    def test_raises_last_error_after_all_retries(self, mock_sleep) -> None:
        def always_fail():
            raise RuntimeError("fail")
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        with self.assertRaises(RuntimeError):
            analyzer._call_ai_with_retry(always_fail)


class TestAuditLog(unittest.TestCase):
    """Tests for ForensicAnalyzer._audit_log."""

    def test_logs_with_audit_logger(self) -> None:
        audit = FakeAuditLogger()
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(audit_logger=audit)
        analyzer._audit_log("test_action", {"key": "value"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0][0], "test_action")

    def test_no_audit_logger_does_not_raise(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        # Should not raise
        analyzer._audit_log("test_action", {"key": "value"})

    def test_broken_audit_logger_does_not_raise(self) -> None:
        class BrokenLogger:
            def log(self, action, details):
                raise RuntimeError("broken")
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(audit_logger=BrokenLogger())
        # Should not raise
        analyzer._audit_log("test_action", {"key": "value"})


class TestSaveCasePrompt(unittest.TestCase):
    """Tests for ForensicAnalyzer._save_case_prompt."""

    def test_saves_prompt_file(self) -> None:
        with TemporaryDirectory(prefix="aift-save-") as tmp_dir:
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            analyzer._save_case_prompt("test.md", "system", "user")
            prompt_path = Path(tmp_dir) / "prompts" / "test.md"
            self.assertTrue(prompt_path.exists())
            content = prompt_path.read_text(encoding="utf-8")
            self.assertIn("system", content)
            self.assertIn("user", content)

    def test_no_case_dir_does_not_raise(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        # Should not raise
        analyzer._save_case_prompt("test.md", "sys", "usr")


class TestResolveArtifactCsvPath(unittest.TestCase):
    """Tests for ForensicAnalyzer._resolve_artifact_csv_path."""

    def test_mapped_path(self) -> None:
        with TemporaryDirectory(prefix="aift-path-") as tmp_dir:
            csv_path = Path(tmp_dir) / "art.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            analyzer = ForensicAnalyzer(artifact_csv_paths={"art": csv_path})
            result = analyzer._resolve_artifact_csv_path("art")
            self.assertEqual(result, csv_path)

    def test_raises_on_missing(self) -> None:
        analyzer = ForensicAnalyzer()
        with self.assertRaises(FileNotFoundError):
            analyzer._resolve_artifact_csv_path("nonexistent_artifact")

    def test_case_dir_parsed_lookup(self) -> None:
        with TemporaryDirectory(prefix="aift-path-") as tmp_dir:
            parsed_dir = Path(tmp_dir) / "parsed"
            parsed_dir.mkdir()
            csv_path = parsed_dir / "runkeys.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            result = analyzer._resolve_artifact_csv_path("runkeys")
            self.assertEqual(result, csv_path)


class TestRegisterArtifactPathsFromMetadata(unittest.TestCase):
    """Tests for ForensicAnalyzer._register_artifact_paths_from_metadata."""

    def test_registers_from_artifact_csv_paths(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifact_csv_paths": {"art1": "/path/to/art1.csv"},
        })
        self.assertIn("art1", analyzer.artifact_csv_paths)

    def test_registers_from_artifacts_container(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifacts": {"art1": {"csv_path": "/path/art1.csv"}},
        })
        self.assertIn("art1", analyzer.artifact_csv_paths)

    def test_none_metadata_does_not_raise(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata(None)

    def test_registers_from_list_container(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifacts": [{"artifact_key": "art1", "csv_path": "/path.csv"}],
        })
        self.assertIn("art1", analyzer.artifact_csv_paths)


class TestRegisterArtifactPathEntry(unittest.TestCase):
    """Tests for ForensicAnalyzer._register_artifact_path_entry."""

    def test_mapping_with_csv_path(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", {"csv_path": "/path.csv"})
        self.assertEqual(analyzer.artifact_csv_paths["art1"], Path("/path.csv"))

    def test_mapping_with_csv_paths_list(self) -> None:
        """Split artifacts with multiple csv_paths preserve all paths."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", {"csv_paths": ["/first.csv", "/second.csv"]})
        self.assertEqual(analyzer.artifact_csv_paths["art1"], [Path("/first.csv"), Path("/second.csv")])

    def test_string_value(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", "/path.csv")
        self.assertEqual(analyzer.artifact_csv_paths["art1"], Path("/path.csv"))

    def test_empty_key_ignored(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("", "/path.csv")
        self.assertEqual(len(analyzer.artifact_csv_paths), 0)

    def test_none_key_ignored(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry(None, "/path.csv")
        self.assertEqual(len(analyzer.artifact_csv_paths), 0)

    def test_single_csv_paths_list_collapses(self) -> None:
        """A csv_paths list with one entry should collapse to a single Path."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", {"csv_paths": ["/only.csv"]})
        self.assertEqual(analyzer.artifact_csv_paths["art1"], Path("/only.csv"))


class TestSplitArtifactCsvHandling(unittest.TestCase):
    """Tests for multi-CSV (split artifact) handling in the analyzer."""

    def test_init_accepts_list_of_paths(self) -> None:
        """ForensicAnalyzer.__init__ stores list[Path] for multi-path artifacts."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": ["/a.csv", "/b.csv"]},
            )
        self.assertIsInstance(analyzer.artifact_csv_paths["evtx"], list)
        self.assertEqual(len(analyzer.artifact_csv_paths["evtx"]), 2)

    def test_init_single_path_stays_path(self) -> None:
        """Single-file artifacts remain a plain Path after init."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": "/runkeys.csv"},
            )
        self.assertIsInstance(analyzer.artifact_csv_paths["runkeys"], Path)

    def test_resolve_artifact_csv_path_returns_first_for_list(self) -> None:
        """_resolve_artifact_csv_path returns the first path for split artifacts."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": ["/first.csv", "/second.csv"]},
            )
        result = analyzer._resolve_artifact_csv_path("evtx")
        self.assertEqual(result, Path("/first.csv"))

    def test_resolve_all_artifact_csv_paths_returns_full_list(self) -> None:
        """_resolve_all_artifact_csv_paths returns all paths for split artifacts."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": ["/a.csv", "/b.csv", "/c.csv"]},
            )
        result = analyzer._resolve_all_artifact_csv_paths("evtx")
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], Path("/a.csv"))
        self.assertEqual(result[2], Path("/c.csv"))

    def test_resolve_all_artifact_csv_paths_single_file(self) -> None:
        """_resolve_all_artifact_csv_paths wraps single Path in a list."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": "/runkeys.csv"},
            )
        result = analyzer._resolve_all_artifact_csv_paths("runkeys")
        self.assertEqual(result, [Path("/runkeys.csv")])

    def test_combine_csv_files(self) -> None:
        """_combine_csv_files merges multiple CSVs into one with all rows."""
        with TemporaryDirectory() as tmpdir:
            csv1 = Path(tmpdir) / "evtx_Security.csv"
            csv2 = Path(tmpdir) / "evtx_System.csv"
            csv1.write_text("ts,msg\n2025-01-01,logon\n2025-01-02,logoff\n", encoding="utf-8")
            csv2.write_text("ts,msg\n2025-02-01,start\n", encoding="utf-8")

            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    artifact_csv_paths={"evtx": [str(csv1), str(csv2)]},
                )
            combined = analyzer._combine_csv_files("evtx", [csv1, csv2])
            self.assertTrue(combined.exists())
            lines = combined.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(lines[0], "ts,msg")
            self.assertEqual(len(lines), 4)  # header + 3 data rows

    def test_combine_csv_files_superset_headers(self) -> None:
        """_combine_csv_files handles CSVs with different column sets."""
        with TemporaryDirectory() as tmpdir:
            csv1 = Path(tmpdir) / "evtx_a.csv"
            csv2 = Path(tmpdir) / "evtx_b.csv"
            csv1.write_text("ts,msg\n2025-01-01,logon\n", encoding="utf-8")
            csv2.write_text("ts,msg,extra\n2025-02-01,start,val\n", encoding="utf-8")

            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer()
            combined = analyzer._combine_csv_files("evtx", [csv1, csv2])
            lines = combined.read_text(encoding="utf-8").strip().splitlines()
            self.assertIn("extra", lines[0])
            self.assertEqual(len(lines), 3)  # header + 2 data rows

    def test_register_from_metadata_preserves_multi_paths(self) -> None:
        """_register_artifact_paths_from_metadata stores list for multi-path entries."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifact_csv_paths": {"evtx": ["/a.csv", "/b.csv"]},
        })
        self.assertIsInstance(analyzer.artifact_csv_paths["evtx"], list)
        self.assertEqual(len(analyzer.artifact_csv_paths["evtx"]), 2)

    def test_analyze_artifact_uses_all_split_csvs(self) -> None:
        """analyze_artifact combines split CSVs before sending to the AI."""
        with TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            (prompts_dir / "artifact_analysis.md").write_text(
                "Key={{artifact_key}}\nData:\n{{data_csv}}\n", encoding="utf-8",
            )
            (prompts_dir / "artifact_analysis_small_context.md").write_text(
                "Key={{artifact_key}}\nData:\n{{data_csv}}\n", encoding="utf-8",
            )
            (prompts_dir / "system_prompt.md").write_text("SYS", encoding="utf-8")
            (prompts_dir / "summary_prompt.md").write_text("SUM", encoding="utf-8")

            csv1 = Path(tmpdir) / "evtx_Security.csv"
            csv2 = Path(tmpdir) / "evtx_System.csv"
            csv1.write_text("ts,msg\n2025-01-01,logon\n", encoding="utf-8")
            csv2.write_text("ts,msg\n2025-02-01,start\n", encoding="utf-8")

            fake_provider = FakeProvider(responses=["AI analysis of split artifact"])
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=tmpdir,
                    artifact_csv_paths={"evtx": [str(csv1), str(csv2)]},
                    prompts_dir=prompts_dir,
                )
                analyzer.ai_provider = fake_provider
            result = analyzer.analyze_artifact("evtx", "test investigation")
            self.assertTrue(result.get("analysis"))
            self.assertNotIn("Analysis failed", result["analysis"])
            # Verify data from both CSVs was present in the prompt
            prompt_sent = fake_provider.calls[0]["user_prompt"]
            self.assertIn("2025-01-01", prompt_sent)
            self.assertIn("2025-02-01", prompt_sent)


class TestConfigureExplicitAnalysisDateRange(unittest.TestCase):
    """Tests for ForensicAnalyzer._configure_explicit_analysis_date_range."""

    def test_valid_range(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._configure_explicit_analysis_date_range({
            "analysis_date_range": {"start_date": "2026-01-01", "end_date": "2026-01-31"},
        })
        self.assertIsNotNone(analyzer._explicit_analysis_date_range)
        self.assertEqual(analyzer._explicit_analysis_date_range[0], datetime(2026, 1, 1))

    def test_invalid_dates(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._configure_explicit_analysis_date_range({
            "analysis_date_range": {"start_date": "invalid", "end_date": "2026-01-31"},
        })
        self.assertIsNone(analyzer._explicit_analysis_date_range)

    def test_reversed_dates(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._configure_explicit_analysis_date_range({
            "analysis_date_range": {"start_date": "2026-12-31", "end_date": "2026-01-01"},
        })
        self.assertIsNone(analyzer._explicit_analysis_date_range)

    def test_none_metadata(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._configure_explicit_analysis_date_range(None)
        self.assertIsNone(analyzer._explicit_analysis_date_range)

    def test_missing_date_range_key(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._configure_explicit_analysis_date_range({"some_key": "value"})
        self.assertIsNone(analyzer._explicit_analysis_date_range)


class TestResolveArtifactMetadata(unittest.TestCase):
    """Tests for ForensicAnalyzer._resolve_artifact_metadata."""

    def test_unknown_key_returns_defaults(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        result = analyzer._resolve_artifact_metadata("completely_unknown_artifact_xyz")
        self.assertEqual(result["name"], "completely_unknown_artifact_xyz")
        self.assertIn("No artifact description", result["description"])


class TestReadModelInfo(unittest.TestCase):
    """Tests for ForensicAnalyzer._read_model_info."""

    def test_returns_provider_info(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.model_info["provider"], "fake")
        self.assertEqual(analyzer.model_info["model"], "fake-model-1")

    def test_broken_provider_returns_unknown(self) -> None:
        class BrokenProvider:
            def get_model_info(self):
                raise RuntimeError("broken")
            def analyze(self, **kwargs):
                return "ok"
        with patch("app.analyzer.core.create_provider", return_value=BrokenProvider()):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.model_info["provider"], "unknown")

    def test_non_mapping_returns_unknown(self) -> None:
        class WeirdProvider:
            def get_model_info(self):
                return "not a dict"
            def analyze(self, **kwargs):
                return "ok"
        with patch("app.analyzer.core.create_provider", return_value=WeirdProvider()):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.model_info["provider"], "unknown")


class TestSetAndResolveAnalysisInputCsvPath(unittest.TestCase):
    """Tests for _set_analysis_input_csv_path and _resolve_analysis_input_csv_path."""

    def test_set_and_resolve(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        path = Path("/some/path.csv")
        analyzer._set_analysis_input_csv_path("runkeys", path)
        result = analyzer._resolve_analysis_input_csv_path("runkeys", Path("/fallback.csv"))
        self.assertEqual(result, path)

    def test_fallback_when_not_set(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        fallback = Path("/fallback.csv")
        result = analyzer._resolve_analysis_input_csv_path("unknown_key", fallback)
        self.assertEqual(result, fallback)


class TestGenerateSummaryFailure(unittest.TestCase):
    """Tests for ForensicAnalyzer.generate_summary error handling."""

    def test_returns_failure_message_on_error(self) -> None:
        fake_provider = FakeProvider(fail_calls={0})
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            with TemporaryDirectory(prefix="aift-sum-") as tmp_dir:
                prompts_dir = Path(tmp_dir) / "prompts"
                prompts_dir.mkdir()
                (prompts_dir / "summary_prompt.md").write_text("{{per_artifact_findings}}", encoding="utf-8")
                (prompts_dir / "system_prompt.md").write_text("sys", encoding="utf-8")
                analyzer = ForensicAnalyzer(
                    case_dir=tmp_dir,
                    audit_logger=FakeAuditLogger(),
                    prompts_dir=prompts_dir,
                )
                result = analyzer.generate_summary([], "ctx", {})
        self.assertTrue(result.startswith("Analysis failed:"))


class TestCreateAiProvider(unittest.TestCase):
    """Tests for ForensicAnalyzer._create_ai_provider."""

    def test_fallback_to_unavailable_provider(self) -> None:
        from app.analyzer.constants import UnavailableProvider
        with patch("app.analyzer.core.create_provider", side_effect=RuntimeError("cannot create")):
            analyzer = ForensicAnalyzer()
        self.assertIsInstance(analyzer.ai_provider, UnavailableProvider)

    def test_default_config_when_no_config(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider) as mock_create:
            analyzer = ForensicAnalyzer()
        # Should have been called with the default local config
        call_args = mock_create.call_args[0][0]
        self.assertIn("ai", call_args)


class TestLoadAnalysisSettings(unittest.TestCase):
    """Tests for ForensicAnalyzer._load_analysis_settings."""

    def test_default_settings(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.ai_max_tokens, 128000)
        self.assertEqual(analyzer.date_buffer_days, 7)
        self.assertTrue(analyzer.artifact_deduplication_enabled)

    def test_custom_settings(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(config={
                "analysis": {
                    "ai_max_tokens": 50000,
                    "date_buffer_days": 3,
                    "artifact_deduplication_enabled": False,
                }
            })
        self.assertEqual(analyzer.ai_max_tokens, 50000)
        self.assertEqual(analyzer.date_buffer_days, 3)
        self.assertFalse(analyzer.artifact_deduplication_enabled)

    def test_non_mapping_analysis_config(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(config={"analysis": "not a dict"})
        # Should use defaults without error
        self.assertEqual(analyzer.ai_max_tokens, 128000)


class TestInitConvenienceShorthand(unittest.TestCase):
    """Tests for ForensicAnalyzer init with mapping as case_dir (convenience shorthand)."""

    def test_mapping_as_case_dir(self) -> None:
        with TemporaryDirectory(prefix="aift-init-") as tmp_dir:
            csv_path = Path(tmp_dir) / "art.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            analyzer = ForensicAnalyzer({"art": csv_path})
        self.assertIsNone(analyzer.case_dir)
        self.assertIn("art", analyzer.artifact_csv_paths)


class TestUnavailableProviderFailsAnalysis(unittest.TestCase):
    """Regression: run_full_analysis must fail immediately with UnavailableProvider."""

    def test_run_full_analysis_raises_on_unavailable_provider(self) -> None:
        """If provider init failed, run_full_analysis must raise AIProviderError."""
        with patch("app.analyzer.core.create_provider", side_effect=RuntimeError("bad key")):
            analyzer = ForensicAnalyzer()

        with self.assertRaises(AIProviderError) as ctx:
            analyzer.run_full_analysis(
                artifact_keys=["runkeys"],
                investigation_context="test",
                metadata=None,
            )
        self.assertIn("bad key", str(ctx.exception))

    def test_run_full_analysis_succeeds_with_valid_provider(self) -> None:
        """Normal providers must not be blocked by the UnavailableProvider guard."""
        fake_provider = FakeProvider(responses=["finding", "summary"])
        with TemporaryDirectory(prefix="aift-ok-") as tmp_dir:
            csv_path = Path(tmp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2024-01-01,test\n", encoding="utf-8")
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=tmp_dir,
                    config={"analysis": {"ai_max_tokens": 4096}},
                    artifact_csv_paths={"runkeys": csv_path},
                )
            result = analyzer.run_full_analysis(
                artifact_keys=["runkeys"],
                investigation_context="test context",
                metadata=None,
            )
        self.assertIn("per_artifact", result)
        self.assertIn("summary", result)


if __name__ == "__main__":
    unittest.main()
