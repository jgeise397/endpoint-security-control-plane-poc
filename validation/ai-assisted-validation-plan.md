# AI-Assisted Validation Plan

This document records the human control points and scoped approval for the five endpoint drift scenarios in this POC. The approval predates execution and is deliberately scoped at the scenario boundary, not repeated for every individual command.

## Control-Point Flow

This is how the validation flow actually ran:

1. Human defined the scope: five named lab endpoints, with attack and drift scenarios limited to lab VMs only.
2. Human enumerated exactly five bounded scenarios in a written pre-authorization manifest before any execution.
3. AI agents generated test procedures within those bounds.
4. Execution and evidence collection are agent-driven on owned lab systems only.
5. The human validates findings, accepts or rejects conclusions, and owns risk decisions.

Moving the human control point earlier, to scope definition and bounded scenario approval, is intentional. The point of this AI-assisted validation design is not to approve every reversible command one at a time. It is to make the boundary explicit before execution, let agents operate inside that boundary, and keep risk decisions with the human.

## Approval Record

Recorded decision from the project owner:

I authorize AI-assisted generation, execution, evidence capture, and cleanup for the five endpoint drift scenarios listed below. This authorization applies only to the named lab VMs and only to reversible actions that do not use malware, steal credentials, create destructive effects, or leave persistence surviving cleanup. The operator's Mac is enrollment-and-posture-read only and is excluded from all attack and drift scenarios.

Approval date: 2026-07-01

Approval type: bounded pre-authorization manifest

Execution status: authorized before execution

## Authorized Scenarios

| Scenario | Target endpoint | Action | Reversal step | Authorized |
|---|---|---|---|---|
| Suspicious PowerShell execution | win-user-01 | Run a benign `powershell -EncodedCommand` command that writes a marker file | Delete the marker file | yes |
| Local admin creation | win-dev-01 | Create `labdrift` and add it to local Administrators | Remove `labdrift` from Administrators and delete the user | yes |
| RDP enabled on the legacy box | win-legacy-01 | Set `fDenyTSConnections=0` and enable the Remote Desktop firewall group | Set `fDenyTSConnections=1` and disable the firewall group | yes |
| Weak SSH configuration | ubuntu-dev-01 | Set `PermitRootLogin yes` and `PasswordAuthentication yes`, then restart sshd | Set both directives back to `no`, validate sshd config, and restart sshd | yes |
| Outdated vulnerable application | win-dev-01 and win-user-01 | Install the same outdated 7-Zip version on both endpoints | Uninstall or upgrade the outdated version and re-check inventory | yes |

## Boundaries

Hard limits for all validation work:

- Owned lab only.
- Lab VMs only for attack and drift scenarios.
- The operator's Mac is posture-read only and excluded from attack and drift scenarios.
- No public or third-party targets.
- No malware.
- No credential theft.
- No persistence surviving cleanup.
- No destructive actions.
- Every scenario must have a documented remediation and re-validation step.
- Threat-intel platform outputs in this repo are sanitized exports only: no credentials, private indicators, or live access details.

Any validation step that cannot stay inside these limits is out of scope until the human redefines and re-approves the scope in writing.
