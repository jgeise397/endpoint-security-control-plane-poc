# Arcane Integration

Arcane is my production threat-intelligence platform: 25+ OSINT enrichers, an ATT&CK cultivation engine, a multi-source confidence plus source-freshness model, and an attribution engine. For this public POC I pointed only its read-only surface at the endpoint findings; this directory contains sanitized outputs and analyst notes, not live access details.

I use Arcane as a decision layer, not a decorative appendix. The useful test is whether it changes the priority of a finding in either direction.

The 7-Zip finding is the clean payoff. `7-Zip 21.07 (x64)` was really installed on `win-user-01` and `win-dev-01`, and CVE-2022-29072 carries CVSS 7.8, which looks ugly on a dashboard. Arcane still scored the context at `0.20` and marked it `low_signal`: local privilege escalation, EPSS `0.0152`, not in CISA KEV, vendor-disputed in NVD, and public exploitation limited to PoC-level signal.

The RDP finding goes the other way. On `win-legacy-01`, exposed RDP maps directly to ATT&CK `T1021.001` and is a lateral-movement front door on a box that cannot take the modern baseline. My response is compensating controls - network isolation, inbound restriction, and RDP disabled by default - not pretending the legacy host can be patched into a different machine.

At capture time, Arcane's background feed workers were stale, with the feed corpus last refreshed on `2026-06-07` and platform health reported as `degraded`; that is the platform demonstrating its own rule that stale intel is worse than no intel.

Security posture of the tooling itself: this repo only gets sanitized-output artifacts, not production data or live access handles. Research egress is forced through VPN plus a Tor kill-switch, and the agents have no direct egress.

Every sample in this directory is sanitized or representative for a public repository. See `sample-arcane-export-redacted.json` for the 7-Zip decision frame, `sample-arcane-rdp-context-redacted.json` for the RDP contrast, `attack-technique-mapping.md` for the lab-to-ATT&CK mapping, and `freshness-confidence-model.md` for how Arcane treats freshness and confidence.
