"""Command-line entry point for offline ScopeProof Lab workflows."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .evidence import EvidenceWriter, verify_chain
from .labs import authz_case, rbac_case
from .report import render_markdown
from .scope import InvalidScope, ScopePolicy, ScopeSession


def _make_self_owned_lab_scope(now: datetime) -> ScopePolicy:
    return ScopePolicy.from_dict({
        "engagement_id": "SYNTHETIC-DEMO-ONLY",
        "authorization_reference": "SELF-OWNED-IN-PROCESS-LAB",
        "lab_only": True, "target_hosts": ["127.0.0.1", "localhost"],
        "source_cidrs": ["127.0.0.1/32"], "ports": [8080],
        "methods": ["synthetic_authz", "rbac_review"],
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "ends_at": (now + timedelta(minutes=15)).isoformat(),
        "max_actions": 4, "stopped": False,
    })


def _fixtures_dir() -> Path:
    # Installed distributions carry the sample JSON alongside this module.
    return Path(__file__).resolve().parent / "fixtures"


def demo(output: Path, policy_path: Path | None = None) -> int:
    now = datetime.now(timezone.utc)
    policy = ScopePolicy.from_file(policy_path) if policy_path else _make_self_owned_lab_scope(now)
    session = ScopeSession(policy)
    if output.exists():
        raise ValueError(f"refusing to overwrite existing output directory: {output}")
    output.mkdir(parents=True)
    with EvidenceWriter(output / "events.jsonl") as log:
        log.record("lab_initialized", {"engagement": policy.engagement_id, "offline": True}, now)
        session.require(url="http://127.0.0.1:8080/synthetic-authz",
                        source_ip="127.0.0.1", method="synthetic_authz", now=now)
        auth_result = authz_case()
        log.record("authz_before_and_after", auth_result, now)
        session.require(url="http://127.0.0.1:8080/synthetic-rbac",
                        source_ip="127.0.0.1", method="rbac_review", now=now)
        folder = _fixtures_dir()
        rbac_result = rbac_case(folder / "rbac_unsafe.json", folder / "rbac_hardened.json")
        log.record("rbac_before_and_after", rbac_result, now)
        results = [auth_result, rbac_result]
        log.record("laboratory_completed", {
            "passed": all(r["before_finding"] and r["after_prevented"] for r in results),
            "scenarios": len(results), "scope_actions": session.actions,
        }, now)
    count, digest = verify_chain(output / "events.jsonl")
    (output / "report.md").write_text(
        render_markdown(policy.engagement_id, results, count, digest), encoding="utf-8"
    )
    if not all(r["before_finding"] and r["after_prevented"] for r in results):
        print("LAB FAILED: see report", file=sys.stderr)
        return 1
    print(f"LAB PASS: {len(results)} scenarios; {count} events; chain head {digest}")
    print(f"Report: {output / 'report.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scopeproof", description="Offline synthetic security lab")
    commands = parser.add_subparsers(dest="cmd", required=True)
    run = commands.add_parser("demo", help="run synthetic before/after labs")
    run.add_argument("--out", type=Path, required=True, help="new output directory")
    run.add_argument("--policy", type=Path, help="optional lab-only scope JSON")
    verify = commands.add_parser("verify", help="verify evidence hash chain")
    verify.add_argument("--events", type=Path, required=True)
    check = commands.add_parser("check-scope", help="validate action locally (no network)")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--url", required=True)
    check.add_argument("--source-ip", required=True)
    check.add_argument("--method", required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "demo":
            return demo(args.out, args.policy)
        if args.cmd == "verify":
            count, digest = verify_chain(args.events)
            print(json.dumps({"ok": True, "events": count, "chain_head": digest}))
            return 0
        if args.cmd == "check-scope":
            policy = ScopePolicy.from_file(args.policy)
            decision = policy.check(url=args.url, source_ip=args.source_ip,
                                    method=args.method)
            print(json.dumps({"allowed": decision.allowed, "reason": decision.reason}))
            return 0 if decision.allowed else 3
        parser.error("unknown command")
    except (InvalidScope, OSError, ValueError, PermissionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2
