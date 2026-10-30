# ScopeProof Lab v0.1 — Synthetic Validation Report

**LAB ONLY / NO EXTERNAL SYSTEMS TESTED**

Engagement reference: `SYNTHETIC-DEMO-ONLY` (self-declared, not verified proof of authorization)

## Controlled scenarios

| ID | Before patch | After patch | Result |
| --- | --- | --- | --- |
| `AUTHZ-LAB-001` | Finding reproduced | Prevented | PASS |
| `RBAC-LAB-001` | Finding reproduced | Prevented | PASS |

## Reproduction and remediation

### AUTHZ-LAB-001

- Synthetic issue: Object ownership was not checked before reading an in-memory object
- Remediation verified: Enforce ownership on every object access and test with two synthetic actors
- Reproduce: `python -m unittest discover -s tests -v` and `scopeproof demo --out ./artifacts/run-unique-name`

### RBAC-LAB-001

- Synthetic issue: Overbroad Kubernetes role permissions in a sample JSON manifest
- Remediation verified: Replace wildcard grants with namespace-bound, least-privilege rules
- Reproduce: `python -m unittest discover -s tests -v` and `scopeproof demo --out ./artifacts/run-unique-name`

## Evidence integrity

- Events recorded: **4**
- Final SHA-256 chain head: `bd2c6eabfa37900aef76da99688b0739f67a81994849e4c5ad8945acfedf8230`
- Verify: `scopeproof verify --events ./artifacts/run-unique-name/events.jsonl`
- Keep the final digest separately to detect subsequent rewrites. A hash chain does not authenticate the operator or demonstrate a signed scope agreement.

## Boundaries

No real customer information, credentials, target addresses, external requests, port scans or vulnerability exploitation are part of this laboratory.
