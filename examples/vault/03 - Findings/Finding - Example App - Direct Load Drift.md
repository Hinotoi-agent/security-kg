---
type: finding
status: draft
severity: High
target: Target - Example App
repo: https://github.com/example-org/example-repo
cwe: CWE-639
tags:
  - idor
  - direct-object-load
pr: https://github.com/example-org/example-repo/pull/123
---

# Finding - Example App - Direct Load Drift

Links to [[Target - Example App]] and #direct-object-load.

## Boundary

Remote user supplies an object ID that reaches a direct object load path.

## Invariant

Direct object loads must enforce the same user/tenant scope as list/query paths.

## Evidence

- Dummy example evidence only.

## Duplicate check

- Example PR: https://github.com/example-org/example-repo/pull/123
