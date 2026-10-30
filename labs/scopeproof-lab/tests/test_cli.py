"""End-to-end CLI smoke tests never open sockets."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scopeproof.cli import main


class CliTests(unittest.TestCase):
    def test_demo_and_verify_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "demo"
            with patch("socket.socket", side_effect=AssertionError("outbound socket used")):
                with contextlib.redirect_stdout(io.StringIO()) as text:
                    result = main(["demo", "--out", str(output)])
                self.assertEqual(result, 0)
                self.assertIn("LAB PASS", text.getvalue())
                with contextlib.redirect_stdout(io.StringIO()) as verify_out:
                    self.assertEqual(main(["verify", "--events", str(output / "events.jsonl")]), 0)
                data = json.loads(verify_out.getvalue())
                self.assertTrue(data["ok"])
                self.assertEqual(data["events"], 4)
                self.assertIn("AUTHZ-LAB-001", (output / "report.md").read_text())
                self.assertIn("RBAC-LAB-001", (output / "report.md").read_text())

    def test_demo_refuses_to_overwrite_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "run"
            self.assertEqual(main(["demo", "--out", str(out)]), 0)
            with contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(main(["demo", "--out", str(out)]), 2)
                self.assertIn("refusing to overwrite", error.getvalue())

    def test_bad_scope_exits_nonzero_without_network(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with patch("socket.socket", side_effect=AssertionError("unexpected socket")):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                result = main([
                    "check-scope", "--policy", str(root / "examples/policy.template.json"),
                    "--url", "https://example.org:443/", "--source-ip", "127.0.0.1",
                    "--method", "synthetic_authz",
                ])
            self.assertEqual(result, 3)
            self.assertFalse(json.loads(out.getvalue())["allowed"])


if __name__ == "__main__":
    unittest.main()
