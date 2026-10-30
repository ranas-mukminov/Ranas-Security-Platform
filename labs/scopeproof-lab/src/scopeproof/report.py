"""Minimal safe report, with synthetic-only content."""

from __future__ import annotations

from typing import Any


def render_markdown(engagement_id: str, results: list[dict[str, Any]],
                    event_count: int, digest: str) -> str:
    parts = [
        "# ScopeProof Lab v0.1 — Synthetic Validation Report",
        "", "**LAB ONLY / NO EXTERNAL SYSTEMS TESTED**", "",
        f"Engagement reference: `{engagement_id}` (self-declared, not verified proof of authorization)",
        "", "## Controlled scenarios", "",
        "| ID | Before patch | After patch | Result |", "| --- | --- | --- | --- |",
    ]
    for case in results:
        bad = bool(case["before_finding"])
        fixed = bool(case["after_prevented"])
        parts.append(
            f"| `{case['case_id']}` | {'Finding reproduced' if bad else 'Not reproduced'} | "
            f"{'Prevented' if fixed else 'Still vulnerable'} | "
            f"{'PASS' if bad and fixed else 'FAIL'} |"
        )
    parts += ["", "## Reproduction and remediation", ""]
    for case in results:
        parts += [
            f"### {case['case_id']}", "",
            f"- Synthetic issue: {case['issue']}",
            f"- Remediation verified: {case['remediation']}",
            "- Reproduce: `python -m unittest discover -s tests -v` and "
            "`scopeproof demo --out ./artifacts/run-unique-name`", "",
        ]
    parts += [
        "## Evidence integrity", "",
        f"- Events recorded: **{event_count}**",
        f"- Final SHA-256 chain head: `{digest}`",
        "- Verify: `scopeproof verify --events ./artifacts/run-unique-name/events.jsonl`",
        "- Keep the final digest separately to detect subsequent rewrites. A hash chain "
        "does not authenticate the operator or demonstrate a signed scope agreement.", "",
        "## Boundaries", "",
        "No real customer information, credentials, target addresses, external requests, "
        "port scans or vulnerability exploitation are part of this laboratory.", "",
    ]
    return "\n".join(parts)
