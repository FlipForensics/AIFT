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
            self.assertEqual(app.config["AIFT_CONFIG_PATH"], str(config_path))


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


if __name__ == "__main__":
    unittest.main()
