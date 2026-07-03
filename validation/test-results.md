# Test results

Actual outcomes from running the five drift scenarios against the live lab. Procedures are in `drift-scenarios.md`; this file records what happened, including the two places the detection did not behave the way the policy alone would suggest. Those are the useful part.

All five scenarios ran on lab VMs only. The real Mac was excluded from every attack, by design.

## 1. Suspicious PowerShell execution (win-user-01)

Ran an encoded (`-EncodedCommand`) PowerShell one-liner. Native PowerShell logging is thin for this on a default box; the depth came from the telemetry layer. Sysmon recorded the process-creation event (EID 1) with the full decoded-in-plain-sight command line, the Wazuh agent forwarded the Sysmon operational channel, and the manager raised **rule 92057 at level 12, mapped to MITRE T1059.001** — "a PowerShell process executed a base64-encoded command." End to end, Sysmon → eventchannel → Wazuh alert, on the first try.

One honest note about the frame: the command was launched through the lab's remote-execution harness, so the event's parent process and account context reflect the harness, not a user session. The evidence that matters — the encoded command line Sysmon preserved when the native logs didn't — is unaffected. Detection: **worked.**

## 2. Local admin creation (win-dev-01) — and the first real gap

Added a local account and put it in Administrators. Two things were supposed to happen: Windows Security event 4732 fires, and the Fleet policy `Local Administrators group matches baseline` flips to fail.

The 4732 event fired **immediately** and was captured. The Fleet policy did not. It re-evaluated twice with the drift present and both times returned pass, while a standalone `osqueryd` run on the same host — same query, pulled straight from Fleet — saw the new admin instantly. The policy only flipped to fail after I recycled the agent's osquery worker.

The cause is worth stating plainly because it changes how you'd design the detection: **osquery caches its expensive Windows account enumeration inside the long-running agent process.** A runtime change to local group membership isn't reflected until that cache turns over. So the periodic policy has a detection-latency floor for this class of change that the policy definition alone doesn't reveal.

The takeaway isn't "the policy is broken" — it's that periodic posture polling and event-driven telemetry are not interchangeable. The 4732 event caught this in real time; the policy is the standing-truth backstop. A mature detection uses both, and knows which one it's trusting for latency. Detection: **worked, with a documented latency floor and a real-time compensating signal.**

## 3. RDP enabled on the legacy box (win-legacy-01)

Enabled RDP via the registry and the firewall group. The Fleet policy `Remote Desktop is disabled` flipped to fail roughly fourteen seconds after the next evaluation — prompt, because this check reads the registry, which osquery does not cache the way it caches account enumeration. That contrast is useful confirmation: the latency floor in scenario 2 is specific to osquery's heavy Windows enumeration tables, not a general property of Fleet.

The finding routes into the legacy exception workflow rather than a generic remediation ticket — RDP on this box is a compensating-control conversation, not a patch (see `../reports/legacy-endpoint-assessment.md`). Threat-intel enrichment for the exposure is captured separately. Detection: **worked.** Remediated and re-validated back to pass.

## 4. Weak SSH configuration (ubuntu-dev-01)

Weakened `sshd_config` to permit root login and password authentication, in the main config file. Both Linux policies — `sshd PermitRootLogin is not enabled` and `sshd PasswordAuthentication is not enabled` — flipped to fail on the next evaluation, then returned to pass after the config was restored. A clean fail-to-pass pair on the cross-platform box.

One scope caveat, documented rather than hidden: these checks parse the main `sshd_config` via osquery's augeas table. A directive placed in a `sshd_config.d/` drop-in is outside this lab check's scope. That's a real limitation of the check as written, and a production version would resolve the effective configuration across the drop-in directory. Detection: **worked, within a stated scope.**

## 5. Outdated vulnerable application (win-user-01 and win-dev-01) — and the gap, again

Installed the same outdated 7-Zip build on two different personas. Software inventory picked it up on both — the finding that feeds the risk model in the next stage, where identical software on a standard user and a developer produces two different priorities.

The denylist policy `No known high-risk software is present` flagged it as failing on win-user-01 straight away. On win-dev-01, Fleet reported pass while a fresh `osqueryd` query on the same box returned fail — the exact caching behavior from scenario 2, this time on the installed-programs table instead of the accounts table. So the latency floor isn't a one-off quirk of one table; it's a property of how the agent caches its expensive Windows enumeration generally. Good to know once, load-bearing everywhere those tables back a drift check. Detection: **worked, same documented latency floor.**

## What this leaves

- **osquery's Windows enumeration caching** (accounts and installed programs) is the headline operational finding. It doesn't stop detection; it bounds the latency and argues for pairing periodic checks with event telemetry. Confirmed on two independent tables.
- **Wazuh security-configuration-assessment and vulnerability detection on macOS are not deployed.** Wazuh was scoped as additive from the start; the agent isn't on the real Mac, so that capability is marked in progress rather than claimed.
- **The SSH drop-in scope** and **the arbitrary browser-version floor** are known, stated limitations, not surprises.

Five scenarios, five detections, two of them teaching something the policy definition didn't. That ratio is the honest yield of running this against real machines instead of describing it.
