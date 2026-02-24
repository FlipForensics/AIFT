from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.chat import ChatManager


class ChatManagerTests(unittest.TestCase):
    @staticmethod
    def _write_csv(path: Path, header: str, rows: list[str]) -> None:
        lines = [header, *rows]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_build_chat_context_includes_expected_sections(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-context-test-") as temp_dir:
            manager = ChatManager(temp_dir)
            context = manager.build_chat_context(
                analysis_results={
                    "summary": "Execution artifacts indicate suspicious lateral movement.",
                    "per_artifact": [
                        {
                            "artifact_name": "Shimcache",
                            "analysis": "Cmd.exe spawned from an unusual temp path.",
                        },
                        {
                            "artifact_name": "Prefetch",
                            "analysis": "PSExec executed multiple times in close succession.",
                        },
                    ],
                },
                investigation_context="Investigate unauthorized admin activity on host WIN-IR-01.",
                metadata={"hostname": "WIN-IR-01", "os_version": "Windows 11", "domain": "CORP"},
            )

        self.assertIn("Investigation Context:", context)
        self.assertIn("System Under Analysis:", context)
        self.assertIn("Executive Summary:", context)
        self.assertIn("Per-Artifact Findings:", context)
        self.assertIn("Hostname: WIN-IR-01", context)
        self.assertIn("OS: Windows 11", context)
        self.assertIn("Domain: CORP", context)
        self.assertIn("Shimcache", context)
        self.assertIn("Prefetch", context)

    def test_retrieve_csv_data_artifact_match_retrieves_target_csv(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-retrieval-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "shimcache.csv",
                "path,sha1",
                [
                    r"C:\Temp\evil.exe,abc123",
                    r"C:\Windows\System32\cmd.exe,def456",
                ],
            )
            self._write_csv(
                parsed_dir / "prefetch.csv",
                "exe,last_run",
                [
                    "cmd.exe,2026-02-20T12:30:00Z",
                ],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="Check the shimcache CSV and show me rows with temp paths.",
                parsed_dir=parsed_dir,
            )

        self.assertTrue(result["retrieved"])
        self.assertEqual(result["artifacts"], ["shimcache.csv"])
        self.assertIn("Artifact: shimcache.csv", result["data"])
        self.assertIn(r"C:\Temp\evil.exe", result["data"])

    def test_retrieve_csv_data_column_match_retrieves_data(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-column-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "net_connections.csv",
                "source_ip,destination_ip,port",
                [
                    "10.0.0.10,10.0.0.55,445",
                    "10.0.0.10,185.199.111.153,443",
                ],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="List records where destination_ip is external.",
                parsed_dir=parsed_dir,
            )

        self.assertTrue(result["retrieved"])
        self.assertEqual(result["artifacts"], ["net_connections.csv"])
        self.assertIn("destination_ip", result["data"])

    def test_retrieve_csv_data_returns_false_when_not_data_request(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-nodata-test-") as temp_dir:
            parsed_dir = Path(temp_dir) / "parsed"
            parsed_dir.mkdir(parents=True, exist_ok=True)
            self._write_csv(
                parsed_dir / "shimcache.csv",
                "path,sha1",
                [r"C:\Temp\evil.exe,abc123"],
            )

            manager = ChatManager(temp_dir)
            result = manager.retrieve_csv_data(
                question="What does this investigation suggest overall?",
                parsed_dir=parsed_dir,
            )

        self.assertEqual(result, {"retrieved": False})

    def test_estimate_token_count_and_max_context_tokens(self) -> None:
        with TemporaryDirectory(prefix="aift-chat-token-test-") as temp_dir:
            manager = ChatManager(temp_dir)
            configured_manager = ChatManager(temp_dir, max_context_tokens=2048)

            self.assertEqual(manager.MAX_CONTEXT_TOKENS, 100000)
            self.assertEqual(configured_manager.MAX_CONTEXT_TOKENS, 2048)
            self.assertEqual(manager.estimate_token_count("abcd" * 10), 10)


if __name__ == "__main__":
    unittest.main()
