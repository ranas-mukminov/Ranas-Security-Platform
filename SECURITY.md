# Security Policy

Ranas Security Platform is built with a security-first mindset. We welcome responsible vulnerability reports and will work with researchers to address issues quickly.

## Reporting a Vulnerability
- Email: security@run-as-daemon.dev
- Preferred subject: "Vulnerability Report – Ranas Security Platform"
- Include: affected component/repository, version or commit hash, impact assessment, reproduction steps or proof-of-concept, and any suggested mitigations.
- Avoid sharing sensitive data. If exploitation requires credentials, use sanitized examples.

## Response Commitments
- **Acknowledgement:** within 2 business days.
- **Triage:** risk assessment and reproduction within 7 business days.
- **Remediation:** coordinated fix timeline based on severity; security fixes are prioritized ahead of feature work.
- **Disclosure:** we will coordinate public disclosure with the reporter after a fix or mitigation is available.

## Secure Communication
- Download the signed PGP public key: https://run-as-daemon.dev/security/pgp.asc  
- If you prefer inline encryption, use the ASCII-armored block below until the hosted key is live and verified.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Ranas Security Stack

[Public key will be published at https://run-as-daemon.dev/security/pgp.asc — replace this block with the hosted key]
-----END PGP PUBLIC KEY BLOCK-----
```

## Scope
This policy covers all repositories under the Ranas Security Stack, including but not limited to Cloud-Audit-Suite, KubeGuardian-Stack, Secure-Infra-Modules, RU-Compliance-Toolkit, and Secure-K3s-GitOps-Template.

## Out of Scope
- Social engineering against team members or customers.
- Denial of service attacks against non-production environments.
- Automated vulnerability scanner output without a clear impact demonstration.

## Preferred Disclosure Process
1. Report privately via email.
2. Work with us to validate and prioritize.
3. Receive CVE (when applicable) and coordinated disclosure timeline.
4. Public advisory issued after fix/mitigation is ready or agreed upon.
