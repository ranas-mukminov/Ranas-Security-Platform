"""Negative tests are deliberately more extensive than allowed-path tests."""

from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from scopeproof.scope import InvalidScope, ScopeDenied, ScopePolicy, ScopeSession

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def valid_scope() -> dict[str, object]:
    return {
        "engagement_id": "LOCAL-SYNTHETIC-TEST", "authorization_reference": "SELF-OWNED-LAB",
        "lab_only": True, "target_hosts": ["127.0.0.1", "localhost", "::1"],
        "source_cidrs": ["127.0.0.1/32", "::1/128"], "ports": [8080],
        "methods": ["synthetic_authz", "rbac_review"],
        "starts_at": (NOW - timedelta(minutes=10)).isoformat(),
        "ends_at": (NOW + timedelta(minutes=10)).isoformat(),
        "max_actions": 2, "stopped": False,
    }


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = valid_scope()
        self.policy = ScopePolicy.from_dict(self.data)

    def check(self, *, url: str = "http://127.0.0.1:8080/mock",
              source_ip: str = "127.0.0.1", method: str = "synthetic_authz",
              now: datetime = NOW) -> bool:
        return self.policy.check(url=url, source_ip=source_ip, method=method, now=now).allowed

    def test_local_action_is_allowed(self) -> None:
        self.assertTrue(self.check())
        self.assertTrue(self.check(url="http://[::1]:8080/mock", source_ip="::1"))

    def test_deny_real_hosts_and_ip_bypass(self) -> None:
        for url in (
            "https://example.org:8080/", "http://192.0.2.2:8080/",
            "http://127.0.0.1:9999/", "http://user:pass@127.0.0.1:8080/",
            "http://127.0.0.1:abc/", "http://127.0.0.1:8080/#fragment",
            "ftp://127.0.0.1:8080/", "http://127.0.0.1.evil.com:8080/",
            "http://[::1", "http://2130706433:8080/",
        ):
            with self.subTest(url=url):
                self.assertFalse(self.check(url=url))
        self.assertFalse(self.check(source_ip="192.0.2.4"))

    def test_deny_unlisted_method(self) -> None:
        self.assertFalse(self.check(method="active_scan"))

    def test_deny_outside_window(self) -> None:
        self.assertFalse(self.check(now=NOW - timedelta(days=1)))
        self.assertFalse(self.check(now=NOW + timedelta(days=1)))
        self.assertFalse(self.check(now=NOW.replace(tzinfo=None)))

    def test_deny_stopped_policy(self) -> None:
        payload = copy.deepcopy(self.data)
        payload["stopped"] = True
        policy = ScopePolicy.from_dict(payload)
        self.assertFalse(policy.check(url="http://127.0.0.1:8080/", source_ip="127.0.0.1",
                                      method="rbac_review", now=NOW).allowed)

    def test_reject_nonlocal_scope_even_when_self_declared(self) -> None:
        for field, bad in (
            ("target_hosts", ["example.org"]),
            ("target_hosts", ["127.0.0.1.evil.com"]),
            ("source_cidrs", ["0.0.0.0/0"]),
            ("source_cidrs", ["192.0.2.0/24"]),
            ("lab_only", False),
            ("methods", ["scan"]),
            ("max_actions", 0),
            ("max_actions", True),
            ("ports", [True]),
            ("stopped", "false"),
            ("authorization_reference", ""),
        ):
            payload = copy.deepcopy(self.data)
            payload[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(InvalidScope):
                ScopePolicy.from_dict(payload)

    def test_reject_missing_timezone_and_invalid_window(self) -> None:
        payload = copy.deepcopy(self.data)
        payload["starts_at"] = "2026-10-31T09:00:00"
        with self.assertRaises(InvalidScope):
            ScopePolicy.from_dict(payload)
        payload["starts_at"] = self.data["ends_at"]
        with self.assertRaises(InvalidScope):
            ScopePolicy.from_dict(payload)

    def test_reject_unknown_key(self) -> None:
        payload = copy.deepcopy(self.data)
        payload["disable_security"] = True
        with self.assertRaises(InvalidScope):
            ScopePolicy.from_dict(payload)

    def test_action_limit_is_enforced(self) -> None:
        session = ScopeSession(self.policy)
        args = dict(url="http://127.0.0.1:8080/mock", source_ip="127.0.0.1",
                    method="rbac_review", now=NOW)
        session.require(**args)
        session.require(**args)
        with self.assertRaisesRegex(ScopeDenied, "maximum"):
            session.require(**args)
        self.assertEqual(session.actions, 2)

    def test_emergency_stop_denies_remaining_action(self) -> None:
        session = ScopeSession(self.policy)
        session.emergency_stop()
        with self.assertRaisesRegex(ScopeDenied, "emergency stop"):
            session.require(url="http://127.0.0.1:8080/mock", source_ip="127.0.0.1",
                            method="synthetic_authz", now=NOW)
        self.assertEqual(session.actions, 0)

    def test_denied_action_does_not_consume_quota(self) -> None:
        session = ScopeSession(self.policy)
        with self.assertRaises(ScopeDenied):
            session.require(url="http://example.org:8080/", source_ip="127.0.0.1",
                            method="synthetic_authz", now=NOW)
        self.assertEqual(session.actions, 0)


if __name__ == "__main__":
    unittest.main()
