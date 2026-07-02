# Threat-Informed Endpoint Security: A Five-Endpoint Control-Plane Case Study

*Fleet/osquery · Wazuh · Sysmon · Python risk scoring · Arcane threat intelligence*

> Working draft. `[E-x.x]` markers are evidence slots defined in the capture checklist; they get replaced with real screenshots and numbers as the lab build produces them. §3 (the five drift scenarios) is deliberately absent from this pre-draft — it gets written from real runs, not ahead of them.

---

## 1. The problem, from the attacker's side

I've spent eight years in incident response and threat intelligence, which means I've mostly seen endpoint security programs at the moment they failed. Almost none of those failures were exotic. The pattern that actually shows up in casework is drift: the firewall rule somebody relaxed during a troubleshooting call and never restored, the local admin account created for a vendor and forgotten, the legacy box that everyone agreed to deal with next quarter for eleven consecutive quarters. The initial access technique varies; the terrain that let it become an incident rarely does.

So I built the control plane I kept wishing the victims had. Five real endpoints — Windows user and developer machines, a macOS workstation, a Linux developer box, and one deliberately legacy Windows host — with desired state defined as code, actual state measured continuously, drift detected in minutes rather than audits, and remediation prioritized by who is actually exploiting what, not by CVSS score alone.

Two framing commitments up front. First: severity is not priority. A critical CVE nobody is exploiting on an isolated box loses to a medium on an exposed developer workstation with a weaponized exploit in active use, and a scoring model that can't express that is decorating reports, not driving decisions. Second: scope honesty. This is a five-endpoint lab with real machines and real telemetry — a working model of the operating loop behind an enterprise endpoint program, not a claim of enterprise scale. Where the difference matters, I say so explicitly (§7).

## 2. Operating model and architecture

The tools are table stakes; the loop is the product:

**define → measure → detect drift → prioritize (threat intel + business context) → remediate → validate → report**

Everything in the stack exists to serve a step in that loop. Fleet and osquery answer posture and inventory questions — is the control present, on, and configured as declared. Sysmon feeding Wazuh provides the security telemetry depth that posture checks can't: not just "is PowerShell logging configured" but the actual encoded command line when it runs. A small Python risk model holds the prioritization opinions, in code, where they can be audited and argued with. And Arcane — my threat intelligence platform, covered in §4 — supplies the context that turns a ranked vulnerability list into a defensible set of decisions.

I want to be precise about what this is not: I am not replicating Jamf, CrowdStrike, or Tenable on a hypervisor. I'm modeling the operating loop those products serve, at a scale where every moving part stays inspectable. On build-vs-buy: at any real fleet size I would buy the measurement layer without hesitation — agents, data pipelines, and console are commodity — and reserve engineering effort for the layers that encode judgment, which is exactly where this POC spends its depth: the prioritization model and the intelligence enrichment. That's also where buying is weakest.

The fleet:

| Endpoint | OS | Persona | Criticality | Exposure |
|---|---|---|---|---|
| win-user-01 | Windows | Standard user | Medium | Normal |
| win-dev-01 | Windows | Developer | High | Elevated |
| mac-user-01 | macOS | Creative user (real workstation) | Medium | Normal |
| ubuntu-dev-01 | Linux | Developer | High | Elevated |
| win-legacy-01 | Windows | Legacy, business-critical | High | Constrained |

Four are VMs on my own hypervisor; mac-user-01 is my actual daily-driver Mac, enrolled for posture measurement and excluded from every attack scenario — because enrolling a real, messy, in-use machine is a more honest test of the measurement layer than a pristine VM.

[E2.1 — architecture diagram]

[E2.2 — Fleet inventory, 5/5 enrolled across three OS platforms]

## 3. Five scenarios: an arc, not a list

*(Written from real runs after Gate 2 — telemetry depth → drift detection → constrained remediation → cross-platform → full prioritization. Covers the OS, App, and App Configuration levels.)*

[E3.1a] [E3.1b] [E3.2] [E3.3a] [E3.4] [E3.5a] [E3.5b]

## 4. Arcane: the intelligence layer

Most pipelines that call themselves threat-informed bolt a feed onto a scanner and call the join a strategy. I run a production threat intelligence platform — Arcane: 25+ OSINT enrichers behind a three-tier enrichment pipeline, an ATT&CK cultivation engine, multi-source confidence laddering, an explicit source-freshness policy, and an attribution engine — and for this POC I pointed it at my own endpoint findings.

The flow is finding → enrichment → decision, and the standard I hold it to is that the intelligence must be able to *change* the decision, not annotate it. The worked example is in §3.5: the same CVE on two endpoints, where Arcane's actor context — is this being used, by whom, against what, how recently — moved one instance up the queue and left the other where CVSS put it. [E4.1 — a single enrichment frame: ATT&CK technique, actor context, source count, freshness date, confidence score.]

Freshness and confidence are first-class fields in that frame, not metadata. Stale intelligence is worse than no intelligence: it spends your credibility on last year's campaign. Arcane timestamps every source, ladders confidence across corroborating sources, and decays what nothing has confirmed recently — so when the model says "actively exploited," that claim has a date and a receipt on it.

One note on the platform's own posture, because tooling that handles threat data is itself an endpoint problem: everything Arcane contributes to this repo is a sanitized export — research egress runs through VPN with a Tor kill-switch, its agents have no direct egress, and no credentials, private indicators, or live-access details leave the platform.

## 5. The legacy endpoint: risk acceptance as a workflow

win-legacy-01 exists in this lab because it exists in every fleet I've ever worked an incident in. Mature endpoint security is not "patch everything immediately" — for some business-critical systems that instruction is a fiction, and programs that pretend otherwise just push the risk into shadow. The mature move is to make the exception a *workflow* with an owner, instead of a shrug with a ticket number.

The exception record for win-legacy-01 is committed in this repo [E5.1]: business owner, technical owner, the specific reason the baseline can't apply, the exact controls affected, the compensating controls with how each one is verified, a quarterly review date, and a retirement plan with a trigger condition. The compensating controls aren't decorative — they're measured by the same Fleet policies as everything else, and §3.3 shows what happens when one of them (RDP stays off) drifts.

Risk translation is part of the workflow, so here is the paragraph the business owner actually gets, written for them: *Your application server can't take current patches, and we're not going to pretend it can. Here's what we've done instead: it can only talk to the two systems it needs, nothing on the internet can reach it, and we watch it more closely than any other machine in the fleet. That reduces the likelihood of compromise substantially, but it doesn't eliminate it — and the residual risk is yours to accept, which is what the signature line is for. We review this together every quarter, and the exception ends when the migration ships or when the compensating controls stop holding, whichever comes first.*

This is the JD's "risk-based approaches rather than policy mandates," practiced rather than quoted.

## 6. genAI on the endpoint

Rapid genAI adoption is changing what an endpoint even is. Developer machines now routinely run AI CLI agents, MCP servers, and AI browser extensions — a new software-inventory class with an unusually interesting data-egress profile, since these tools exist specifically to read things and send them somewhere. Most inventory programs haven't caught up: they can tell you Chrome is outdated, but not that an agent with shell access enrolled itself last Tuesday. In this lab, osquery's software and process inventory on the developer endpoints picks up the AI tooling footprint like any other package — which is precisely the point: it should be inventory, not folklore. [E6.1 — optional: inventory query filtered to AI tooling on win-dev-01.]

I hold an unusual vantage point on this problem: I operate a production fleet of autonomous AI agents, so I've had to solve their endpoint posture from the operator's chair — least-privilege service users per agent, secrets isolation, restricted SSH for anything that writes, egress-controlled containers for anything that fetches. The controls that transfer to workforce endpoints are the boring ones: inventory the agents like software (because they are), scope their credentials like service accounts (because they are), and gate their writes behind human approval where the blast radius warrants it. Same discipline, new package names.

## 7. At enterprise scale, and what the numbers say

Translating this lab honestly: the Fleet policy pack maps to MDM compliance in Jamf, Kandji, or Intune plus CrowdStrike or Tenable doing detection and vulnerability coverage at scale; the Python risk model is the prioritization logic that lives inside a vulnerability management program, here made small enough to read; the exception record is what an exception *system* — with SLAs, aging metrics, and escalation — manages in the thousands. The lab's job was never to replace those; it was to demonstrate command of the operating loop they implement, on infrastructure where nothing is hidden behind a vendor console.

The numbers, as decision inputs rather than dashboard art:

- Enrollment coverage: [5/5 endpoints, 3 OS platforms — from E2.2]
- Controls measured: [N, per-OS split — from Gate 2 first run]
- First-run policy pass rate: [X of N — recorded honestly, the failures are the interesting part]
- Drift scenarios detected: [N/5, with the gap analysis for anything missed]
- Time-to-detect for admin-drift: [minutes, from E3.2 timestamp]
- Findings re-prioritized by intelligence context: [N — from Gate 3]

What's unfinished, stated plainly: [populated at Gate 4 — e.g., Wazuh coverage gaps, macOS SCA status, anything shipped as "in progress." The rough edges stay in the document on purpose; a POC with no visible tradeoffs is describing someone else's build.]
