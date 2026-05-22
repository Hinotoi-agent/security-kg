# Security Policy

## Reporting vulnerabilities

If you find a vulnerability in VulnWeave itself, please open a private disclosure through GitHub Security Advisories when available, or contact the maintainer with enough detail to reproduce the issue safely.

Please include:

- affected version or commit
- vulnerable command or workflow
- minimal safe reproduction steps
- expected vs actual behavior
- impact and trust boundary
- suggested remediation if known

## Scope

In scope:

- command injection, path traversal, or unsafe file writes in VulnWeave commands
- parsing bugs that can cause unexpected host-side file access or overwrite
- unsafe handling of untrusted vault/repo contents
- security-relevant false-negative/false-positive patterns with a clear invariant gap

Out of scope:

- results produced by intentionally malicious target repositories unless VulnWeave mishandles them on the host
- generic detector quality requests without a concrete security impact
- vulnerabilities in third-party tools or example target applications

## Philosophy

VulnWeave is a local-first research assistant. It should never require uploading private source code or vault contents to a remote service to perform its core workflow.
