"""Synthetic security demonstrations only. There are no network calls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    identifier: str
    severity: str
    title: str
    explanation: str


class ToyDocumentService:
    """Small in-memory API authorization model; nothing is listening on a port."""

    def __init__(self, *, enforce_owner: bool) -> None:
        self.enforce_owner = enforce_owner
        self._documents = {"invoice-001": {"owner": "alice", "content": "SYNTHETIC-ONLY"}}

    def read(self, *, actor: str, document_id: str) -> str:
        doc = self._documents.get(document_id)
        if doc is None:
            raise KeyError("document not found")
        if self.enforce_owner and doc["owner"] != actor:
            raise PermissionError("actor is not the owner")
        return doc["content"]


def authz_case() -> dict[str, object]:
    """Demonstrate a *deliberately vulnerable* and a patched authz check."""
    before = ToyDocumentService(enforce_owner=False)
    vulnerable = before.read(actor="bob", document_id="invoice-001") == "SYNTHETIC-ONLY"
    patched = ToyDocumentService(enforce_owner=True)
    try:
        patched.read(actor="bob", document_id="invoice-001")
    except PermissionError:
        fixed = True
    else:
        fixed = False
    return {
        "case_id": "AUTHZ-LAB-001", "synthetic": True,
        "issue": "Object ownership was not checked before reading an in-memory object",
        "before_finding": vulnerable,
        "after_prevented": fixed,
        "remediation": "Enforce ownership on every object access and test with two synthetic actors",
    }


def analyze_rbac(role: dict[str, object]) -> list[Finding]:
    """Limited, explainable checks for *synthetic* Role/ClusterRole JSON fixtures."""
    if role.get("kind") not in {"Role", "ClusterRole"}:
        raise ValueError("expected a Kubernetes Role or ClusterRole JSON fixture")
    rules = role.get("rules")
    if not isinstance(rules, list):
        raise ValueError("role must contain an array of rules")
    findings: list[Finding] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError("malformed RBAC rule")
        verbs, resources, groups = (rule.get(k, []) for k in ("verbs", "resources", "apiGroups"))
        if any(not isinstance(x, list) or not all(isinstance(v, str) for v in x)
               for x in (verbs, resources, groups)):
            raise ValueError("RBAC rule verbs, resources and apiGroups must be string arrays")
        if "*" in verbs and "*" in resources:
            findings.append(Finding(
                f"RBAC-LAB-001-R{index}", "high", "Wildcard resource permissions",
                "Both resources and verbs are wildcarded; use specific resources and actions.",
            ))
        if "secrets" in resources and any(v in verbs for v in ("get", "list", "watch", "*")):
            findings.append(Finding(
                f"RBAC-LAB-002-R{index}", "medium", "Secret reading permissions",
                "Read access to Secrets should be explicitly justified and scoped.",
            ))
    return findings


def load_role(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("RBAC fixture must be a JSON object")
    return value


def rbac_case(unsafe: Path, hardened: Path) -> dict[str, object]:
    before = analyze_rbac(load_role(unsafe))
    after = analyze_rbac(load_role(hardened))
    return {
        "case_id": "RBAC-LAB-001", "synthetic": True,
        "issue": "Overbroad Kubernetes role permissions in a sample JSON manifest",
        "before_finding": bool(before), "after_prevented": not bool(after),
        "before_codes": [f.identifier for f in before],
        "after_codes": [f.identifier for f in after],
        "remediation": "Replace wildcard grants with namespace-bound, least-privilege rules",
    }
