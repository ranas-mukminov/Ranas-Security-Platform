"""Validate exactly what the two synthetic examples claim to demonstrate."""

import unittest
from pathlib import Path

from scopeproof.labs import ToyDocumentService, analyze_rbac, authz_case, load_role, rbac_case

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "src" / "scopeproof" / "fixtures"


class AuthzLabTests(unittest.TestCase):
    def test_authz_before_after(self) -> None:
        result = authz_case()
        self.assertTrue(result["synthetic"])
        self.assertTrue(result["before_finding"])
        self.assertTrue(result["after_prevented"])
        self.assertEqual(result["case_id"], "AUTHZ-LAB-001")

    def test_owner_is_allowed_in_patched_version(self) -> None:
        secure = ToyDocumentService(enforce_owner=True)
        self.assertEqual(secure.read(actor="alice", document_id="invoice-001"),
                         "SYNTHETIC-ONLY")

    def test_nonowner_is_denied_in_patched_version(self) -> None:
        secure = ToyDocumentService(enforce_owner=True)
        with self.assertRaises(PermissionError):
            secure.read(actor="bob", document_id="invoice-001")
        with self.assertRaises(KeyError):
            secure.read(actor="alice", document_id="missing")


class RbacLabTests(unittest.TestCase):
    def test_bad_role_is_flagged_and_hardened_role_is_clean(self) -> None:
        before = analyze_rbac(load_role(FIXTURES / "rbac_unsafe.json"))
        after = analyze_rbac(load_role(FIXTURES / "rbac_hardened.json"))
        self.assertEqual(len(before), 1)
        self.assertEqual(before[0].severity, "high")
        self.assertFalse(after)

    def test_role_case_report(self) -> None:
        result = rbac_case(FIXTURES / "rbac_unsafe.json",
                           FIXTURES / "rbac_hardened.json")
        self.assertTrue(result["before_finding"])
        self.assertTrue(result["after_prevented"])
        self.assertEqual(result["after_codes"], [])

    def test_secret_read_is_reported(self) -> None:
        role = {"kind": "Role", "rules": [{"apiGroups": [""],
                "resources": ["secrets"], "verbs": ["get"]}]}
        findings = analyze_rbac(role)
        self.assertEqual(findings[0].severity, "medium")

    def test_reject_malformed_roles(self) -> None:
        for role in ({"kind": "Pod", "rules": []},
                     {"kind": "Role", "rules": "*"},
                     {"kind": "Role", "rules": [{"verbs": True}]}):
            with self.subTest(role=role), self.assertRaises(ValueError):
                analyze_rbac(role)


if __name__ == "__main__":
    unittest.main()
