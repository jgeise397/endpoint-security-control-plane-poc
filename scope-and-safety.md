# Scope And Safety

## What this is

This is authorized security validation on a lab I own. The POC covers five endpoints: four VMs on my own hypervisor and my own workstation as the macOS enrollment target.

The lab network is isolated from public and third-party targets. Example lab addressing may use ranges such as `192.168.56.x`; no production hostnames, private infrastructure paths, credentials, or live access details belong in this repo.

## AI-assisted validation, framed precisely

This work uses AI-assisted adversary emulation and control validation. It is not autonomous offensive activity; sloppy labels hide who approved what, where it ran, and how cleanup was proven.

The human control points are fixed:

1. Human defines scope.
2. AI generates the test plan.
3. Human approves the plan in writing.
4. Execution happens on owned lab systems only.
5. Tooling collects evidence.
6. AI summarizes the results.
7. Human validates findings and makes risk decisions.

Scope for the five drift scenarios in this POC was defined and approved in writing by the operator on 2026-07-01, before any scenario ran. The macOS workstation is enrollment-and-posture-read only and is excluded from all attack and drift scenarios.

## Hard boundaries

- Owned lab only.
- No public or third-party targets.
- No malware.
- No credential theft.
- No persistence surviving cleanup.
- No destructive actions.
- Every scenario has a documented remediation and re-validation step.
- Threat-intel platform outputs included here are sanitized exports only: no credentials, no private indicators, and no live access details.

Validation work that cannot show its authorization and rollback story is indistinguishable from recklessness.
