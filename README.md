# Endpoint Security Control Plane POC

Eight years of incident response and threat intelligence taught me that endpoint programs rarely lose to 0-days — they lose to drift, slowly, and then all at once. This repo is a working five-endpoint control plane built around that lesson: desired state as code, actual state measured continuously, drift detected fast, and remediation prioritized by who is actually exploiting what rather than by CVSS arithmetic. Everything here ran on real machines; the interesting parts are the opinions, and they are all in files you can read.

## The Fleet

| Endpoint | Persona | OS | Criticality | Exposure |
| --- | --- | --- | --- | --- |
| `win-user-01` | Standard user | Windows | Medium | Normal |
| `win-dev-01` | Developer | Windows | High | Elevated |
| `mac-user-01` | Creative user, real workstation | macOS | Medium | Normal |
| `ubuntu-dev-01` | Linux developer | Linux | High | Elevated |
| `win-legacy-01` | Legacy business-critical host | Windows | High | Constrained |

## Operating Loop

`define -> measure -> detect drift -> prioritize (threat intel + business context) -> remediate -> validate -> report`

Fleet and osquery define and measure posture: is the declared control present, enabled, and reporting. Sysmon and Wazuh capture telemetry for the parts posture cannot explain, including process behavior and command lines. The Python risk model prioritizes remediation by combining exploit pressure, business context, endpoint persona, legacy uplift, and named compensating controls. Arcane enriches the lab's own findings so threat intelligence can change the queue, not just decorate it. The markdown reports preserve the decision trail for technical review and executive translation.

## What's Real and What's Modeled

This is five real endpoints, real telemetry, and real drift scenarios. It is a model of the operating loop at inspectable scale, not a claim that five machines prove enterprise scale. The point is to make the judgment visible: controls as data, findings as ranked evidence, and exceptions with owners instead of folklore.

## Arcane

Arcane is my production threat-intelligence platform: 25+ OSINT enrichers, a three-tier enrichment pipeline, ATT&CK cultivation, confidence laddering, and a source-freshness policy. For this lab, I pointed it at the endpoint findings instead of a toy feed. Everything from Arcane in this repo is a sanitized export: no credentials, no private indicators, and no live-access details. The standard is simple: enrichment has to be strong enough to move a remediation decision.

## Scope and Safety

All validation ran on an owned, isolated lab, and the scope was approved in writing before any scenario ran; the boundaries are documented in [scope-and-safety.md](scope-and-safety.md).

## Repo Map

- [README.md](README.md) - front-door summary for a short reviewer skim.
- [architecture.md](architecture.md) - system diagram, stack rationale, build-vs-buy position, and data flow.
- [endpoint-fleet/](endpoint-fleet/) - endpoint personas, posture-control catalog, and the legacy exception record.
- [fleet/](fleet/) - the deployed policy pack per OS, first-run posture numbers recorded honestly, and console captures.
- [validation/](validation/) - the approved validation plan, the five drift-scenario procedures, and what actually happened when they ran (including the detection gaps).
- [arcane-integration/](arcane-integration/) - sanitized threat-intel exports and the freshness/confidence model behind the prioritization calls.
- [risk-scoring/](risk-scoring/) - Python scoring model, sample findings, tests, and generated prioritized findings.
- [reports/](reports/) - the case study this repo backs, as markdown and as the submitted PDF.
- [scope-and-safety.md](scope-and-safety.md) - authorization, lab boundaries, and validation limits.

The narrative version of this build — scenario evidence, the worked prioritization example, and the parts that didn't behave — is [reports/case-study.md](reports/case-study.md) ([PDF](reports/endpoint-security-case-study.pdf)).
