# First-run policy posture

The honest numbers from the first policy evaluation across the fleet, before any remediation. The point of recording these is that a first run on real machines is never clean, and the failures are more informative than the passes.

Twenty-six policies are deployed: ten Windows, eight macOS, eight Linux. Fleet evaluates them on the host's detail-query interval, so the numbers below are what each host reported once its first post-deployment evaluation landed.

| Host | OS | Passed | Notable failures |
|---|---|---|---|
| win-user-01 | Windows | 7 / 10 | BitLocker, screen-lock timeout, outdated browser |
| win-dev-01 | Windows | 7 / 10 | BitLocker, screen-lock timeout, outdated browser |
| win-legacy-01 | Windows | 7 / 10 | BitLocker, screen-lock timeout, outdated browser |
| ubuntu-dev-01 | Linux | 7 / 8 | auditd not present |
| mac-user-01 | macOS | 4 / 8 | application firewall off, local-admin baseline, screen lock, updates behind |

A few of these deserve a straight explanation rather than a remediation ticket.

**The Windows failures are mostly the eval environment being honest about itself.** These are evaluation VMs, not managed corporate hardware. BitLocker fails because there's no TPM-backed protector provisioned — on a real endpoint enrolled in an MDM this is a compliance win, here it's an accurate reading of an unmanaged disk. The screen-lock policy fails for the same reason: no inactivity timeout has been pushed, because nothing is pushing policy to these boxes except the thing measuring them. I left both failing rather than hand-set them, because a green board I hand-arranged proves nothing.

**The outdated-browser floor is deliberately aggressive, and I'd tune it in production.** The policy flags the shipped Edge build against a pinned version floor. In the lab the floor is a hard-coded number; in a real program it would be fed from a browser-version service so "outdated" tracks the actual support window instead of a constant I picked. I'm calling it out because a policy that's technically firing but on an arbitrary threshold is the kind of thing that quietly trains people to ignore the board.

**mac-user-01 is the most interesting row, precisely because it's a real machine.** FileVault, Gatekeeper, and System Integrity Protection all pass — the disk-and-code-integrity story on my actual workstation is solid. The application firewall being off and the local-admin set not matching a lab baseline are real drift on a real, in-use machine, which is the whole reason I enrolled it instead of a clean VM. This is the row that would start a conversation with a human owner, not an auto-remediation.

**auditd on Linux** is a genuine gap: the cloud image doesn't ship it, and "logging is present" should mean more than syslog. It's a real finding, not an artifact.

These first-run numbers are the baseline the drift scenarios move against — see `../validation/test-results.md`.
