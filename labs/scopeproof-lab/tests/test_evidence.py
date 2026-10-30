"""Evidence is tamper-evident, not cryptographically attributable."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scopeproof.evidence import EvidenceWriter, verify_chain


class EvidenceTests(unittest.TestCase):
    def test_roundtrip_and_detection_of_modified_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "events.jsonl"
            with EvidenceWriter(file) as writer:
                writer.record("a", {"safe": "synthetic"})
                writer.record("b", {"passed": True})
            count, digest = verify_chain(file)
            self.assertEqual(count, 2)
            self.assertEqual(len(digest), 64)
            lines = file.read_text(encoding="utf-8").splitlines()
            item = json.loads(lines[0])
            item["details"]["safe"] = "tampered"
            lines[0] = json.dumps(item)
            file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_chain(file)

    def test_empty_chain_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "empty.jsonl"
            p.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                verify_chain(p)

    def test_chain_cannot_be_overwritten_by_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "events.jsonl"
            with EvidenceWriter(p) as writer:
                writer.record("one", {})
            with self.assertRaises(FileExistsError):
                EvidenceWriter(p)

    def test_naive_timestamp_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "events.jsonl"
            with EvidenceWriter(p) as writer:
                with self.assertRaises(ValueError):
                    writer.record("one", {}, datetime(2026, 10, 31))
                writer.record("valid", {}, datetime(2026, 10, 31, tzinfo=timezone.utc))
            self.assertEqual(verify_chain(p)[0], 1)

    def test_bad_order_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "events.jsonl"
            with EvidenceWriter(p) as writer:
                writer.record("first", {})
                writer.record("second", {})
            lines = p.read_text(encoding="utf-8").splitlines()
            p.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sequence"):
                verify_chain(p)


if __name__ == "__main__":
    unittest.main()
