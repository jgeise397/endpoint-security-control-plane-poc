"""Score endpoint vulnerability findings with endpoint persona context.

The model joins CSV findings to endpoint personas, normalizes every factor to
0-1, computes a weighted score, applies legacy endpoint uplift, subtracts named
compensating controls, and renders a ranked markdown briefing.

LIMITATIONS:
- The weights are static and have no calibration data behind them.
- The arcane context score has no temporal decay, so stale intel can stay loud.
- Compensating-control values are judgment calls, not measurements.
- Production would add an EPSS refresh feed, exploit-maturity decay, and
  per-control effectiveness evidence instead of trusting static constants.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CSV_PATH = SCRIPT_DIR / "sample_vulnerabilities.csv"
DEFAULT_PERSONAS_PATH = SCRIPT_DIR.parent / "endpoint-fleet" / "endpoint-personas.yaml"
DEFAULT_OUTPUT_PATH = SCRIPT_DIR / "prioritized_findings.md"

REQUIRED_COLUMNS = (
    "finding_id",
    "endpoint",
    "cve",
    "cvss",
    "epss",
    "kev",
    "exploit_available",
    "arcane_context_score",
    "arcane_context_note",
)

WEIGHTS: dict[str, float] = {
    "cvss": 16.0,  # CVSS keeps engineering severity visible, but it does not get to outrank live exploitation by itself.
    "epss": 20.0,  # EPSS estimates exploitation pressure, which is closer to priority than impact math.
    "kev": 22.0,  # KEV outweighs raw CVSS because observed exploitation beats theoretical worst case.
    "exploit_available": 14.0,  # A weaponized exploit turns "possible" into "repeatable enough for busy attackers."
    "arcane_context": 10.0,  # Local intel belongs in the score because the internet is not your fleet.
    "criticality": 7.0,  # Business importance should move rank, but it should not bury exploit evidence.
    "exposure": 6.0,  # Reachability changes the path length, so it earns points without becoming the whole model.
    "persona_risk": 5.0,  # Persona risk captures workflow blast radius and stays small because it is compressed judgment.
}

# These are explicit point buy-downs for auditability, not precise measurements.
COMPENSATING_CONTROL_VALUES: dict[str, float] = {
    "network_isolation": 10.0,  # Segmentation blocks whole exploit paths, so it earns a double-digit buy-down.
    "inbound_restriction": 7.0,  # Inbound filtering is material, but user-driven and outbound paths remain.
    "rdp_disabled_default": 6.0,  # Removing default RDP kills a common lateral-movement shortcut, not the bug.
    "reduced_local_admin": 5.0,  # Lower local privilege is containment after compromise, not prevention.
}

EXPLOIT_AVAILABLE_VALUES = {"none": 0.0, "poc": 0.5, "weaponized": 1.0}
CRITICALITY_VALUES = {"low": 0.3, "medium": 0.6, "high": 1.0}
EXPOSURE_VALUES = {"normal": 0.5, "elevated": 0.8, "constrained": 1.0}


@dataclass(frozen=True)
class EndpointPersona:
    hostname: str
    persona: str
    os: str
    criticality: str
    exposure: str
    persona_risk: float
    legacy_multiplier: float
    compensating_controls: tuple[str, ...]


@dataclass(frozen=True)
class VulnerabilityFinding:
    finding_id: str
    endpoint: str
    cve: str
    cvss: float
    epss: float
    kev: bool
    exploit_available: str
    arcane_context_score: float
    arcane_context_note: str


@dataclass(frozen=True)
class FactorBreakdown:
    normalized_value: float
    weight: float
    contribution: float


@dataclass(frozen=True)
class FindingScore:
    finding: VulnerabilityFinding
    persona: EndpointPersona
    factors: dict[str, FactorBreakdown]
    base_score: float
    legacy_multiplier: float
    score_after_legacy_multiplier: float
    control_subtractions: dict[str, float]
    total_control_subtraction: float
    final_score: float


def load_personas(path: Path = DEFAULT_PERSONAS_PATH) -> dict[str, EndpointPersona]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping of endpoint hostnames")

    required = (
        "persona",
        "os",
        "criticality",
        "exposure",
        "persona_risk",
        "legacy_multiplier",
        "compensating_controls",
    )
    personas: dict[str, EndpointPersona] = {}
    for hostname, values in raw.items():
        if not isinstance(values, dict):
            raise ValueError(f"persona {hostname}: expected mapping")
        missing = [field for field in required if field not in values]
        if missing:
            raise ValueError(
                f"persona {hostname}: missing field(s) {', '.join(missing)}"
            )
        controls = values["compensating_controls"]
        if not isinstance(controls, list):
            raise ValueError(
                f"persona {hostname}: compensating_controls must be a list"
            )
        unknown_controls = sorted(set(controls) - set(COMPENSATING_CONTROL_VALUES))
        if unknown_controls:
            raise ValueError(
                f"persona {hostname}: unknown compensating control(s) {', '.join(unknown_controls)}"
            )
        criticality, exposure = str(values["criticality"]), str(values["exposure"])
        if criticality not in CRITICALITY_VALUES:
            raise ValueError(f"persona {hostname}: criticality has unsupported value")
        if exposure not in EXPOSURE_VALUES:
            raise ValueError(f"persona {hostname}: exposure has unsupported value")
        personas[str(hostname)] = EndpointPersona(
            hostname=str(hostname),
            persona=str(values["persona"]),
            os=str(values["os"]),
            criticality=criticality,
            exposure=exposure,
            persona_risk=_persona_float(
                str(hostname), "persona_risk", values["persona_risk"]
            ),
            legacy_multiplier=_persona_float(
                str(hostname), "legacy_multiplier", values["legacy_multiplier"]
            ),
            compensating_controls=tuple(str(control) for control in controls),
        )
    return personas


def load_findings(
    csv_path: Path, personas: Mapping[str, EndpointPersona]
) -> list[VulnerabilityFinding]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing_columns = [
            column
            for column in REQUIRED_COLUMNS
            if column not in (reader.fieldnames or [])
        ]
        if missing_columns:
            raise ValueError(
                f"row 1 field {missing_columns[0]}: missing required column"
            )
        findings: list[VulnerabilityFinding] = []
        for row_number, row in enumerate(reader, start=2):
            for field in REQUIRED_COLUMNS:
                if _clean(row.get(field)) == "":
                    raise ValueError(f"row {row_number} field {field}: missing value")
            endpoint = _clean(row["endpoint"])
            if endpoint not in personas:
                raise ValueError(
                    f"row {row_number} field endpoint: unknown endpoint {endpoint!r}"
                )
            findings.append(
                VulnerabilityFinding(
                    finding_id=_clean(row["finding_id"]),
                    endpoint=endpoint,
                    cve=_clean(row["cve"]),
                    cvss=_number(row_number, "cvss", row["cvss"], 0.0, 10.0),
                    epss=_number(row_number, "epss", row["epss"], 0.0, 1.0),
                    kev=_bool(row_number, "kev", row["kev"]),
                    exploit_available=_exploit(row_number, row["exploit_available"]),
                    arcane_context_score=_number(
                        row_number,
                        "arcane_context_score",
                        row["arcane_context_score"],
                        0.0,
                        1.0,
                    ),
                    arcane_context_note=_clean(row["arcane_context_note"]),
                )
            )
    return findings


def score_csv(
    csv_path: Path = DEFAULT_CSV_PATH, personas_path: Path = DEFAULT_PERSONAS_PATH
) -> list[FindingScore]:
    personas = load_personas(personas_path)
    scores = [
        score_finding(finding, personas[finding.endpoint])
        for finding in load_findings(csv_path, personas)
    ]
    return sorted(
        scores, key=lambda score: (-score.final_score, score.finding.finding_id)
    )


def score_finding(
    finding: VulnerabilityFinding, persona: EndpointPersona
) -> FindingScore:
    normalized = {
        "cvss": finding.cvss / 10.0,
        "epss": finding.epss,
        "kev": 1.0 if finding.kev else 0.0,
        "exploit_available": EXPLOIT_AVAILABLE_VALUES[finding.exploit_available],
        "arcane_context": finding.arcane_context_score,
        "criticality": CRITICALITY_VALUES[persona.criticality],
        "exposure": EXPOSURE_VALUES[persona.exposure],
        "persona_risk": persona.persona_risk,
    }
    weight_total = sum(WEIGHTS.values())
    factors = {
        name: FactorBreakdown(
            value, WEIGHTS[name], (value * WEIGHTS[name] / weight_total) * 100.0
        )
        for name, value in normalized.items()
    }
    base_score = sum(factor.contribution for factor in factors.values())

    # Multiply first: everything is worse on a box that cannot be patched.
    # Controls then buy back specific, named risk instead of hiding it in the multiplier.
    score_after_multiplier = base_score * persona.legacy_multiplier
    controls = {
        control: COMPENSATING_CONTROL_VALUES[control]
        for control in persona.compensating_controls
    }
    final_score = max(0.0, min(100.0, score_after_multiplier - sum(controls.values())))
    return FindingScore(
        finding=finding,
        persona=persona,
        factors=factors,
        base_score=base_score,
        legacy_multiplier=persona.legacy_multiplier,
        score_after_legacy_multiplier=score_after_multiplier,
        control_subtractions=controls,
        total_control_subtraction=sum(controls.values()),
        final_score=final_score,
    )


def render_markdown(scores: Sequence[FindingScore]) -> str:
    lines = [
        "# Prioritized Findings",
        "",
        "| Rank | Finding ID | Endpoint | CVE | Final score |",
        "| ---: | --- | --- | --- | ---: |",
    ]
    for rank, score in enumerate(scores, start=1):
        lines.append(
            f"| {rank} | {score.finding.finding_id} | {score.finding.endpoint} | {score.finding.cve} | {score.final_score:.2f} |"
        )
    lines.extend(["", "## Factor Breakdown"])
    for rank, score in enumerate(scores, start=1):
        lines.extend(
            [
                "",
                f"### {rank}. {score.finding.finding_id} - {score.finding.endpoint} - {score.finding.cve}",
                "",
                f"Context note: {score.finding.arcane_context_note}",
                "",
                "| Line item | Normalized value | Weight | Contribution |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for factor_name in WEIGHTS:
            factor = score.factors[factor_name]
            lines.append(
                f"| {factor_name} | {factor.normalized_value:.3f} | {factor.weight:.1f} | {factor.contribution:.2f} |"
            )
        lines.append(f"| base_score |  |  | {score.base_score:.2f} |")
        lines.append(
            f"| legacy_multiplier | x{score.legacy_multiplier:.2f} |  | {score.score_after_legacy_multiplier:.2f} |"
        )
        if score.control_subtractions:
            for control, value in score.control_subtractions.items():
                lines.append(f"| control:{control} |  |  | -{value:.2f} |")
        else:
            lines.append("| controls |  |  | -0.00 |")
        lines.append(f"| final_score |  |  | {score.final_score:.2f} |")
    return "\n".join([*lines, ""])


def write_report(
    csv_path: Path = DEFAULT_CSV_PATH,
    personas_path: Path = DEFAULT_PERSONAS_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
) -> list[FindingScore]:
    scores = score_csv(csv_path, personas_path)
    output_path.write_text(render_markdown(scores), encoding="utf-8")
    return scores


def main() -> None:
    scores = write_report()
    pair = {
        score.finding.endpoint: score
        for score in scores
        if score.finding.cve == "CVE-2022-29072"
    }
    print(f"Loaded {len(scores)} findings from {DEFAULT_CSV_PATH.name}")
    print(f"Wrote {DEFAULT_OUTPUT_PATH.name} with {len(scores)} ranked findings")
    print(
        f"CVE-2022-29072 pair: win-user-01={pair['win-user-01'].final_score:.2f}, win-dev-01={pair['win-dev-01'].final_score:.2f}"
    )


def _clean(value: str | None) -> str:
    return "" if value is None else value.strip()


def _number(
    row_number: int, field: str, raw_value: str, minimum: float, maximum: float
) -> float:
    try:
        value = float(_clean(raw_value))
    except ValueError as exc:
        raise ValueError(f"row {row_number} field {field}: expected a number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(
            f"row {row_number} field {field}: expected {minimum:g}-{maximum:g}, got {value:g}"
        )
    return value


def _bool(row_number: int, field: str, raw_value: str) -> bool:
    value = _clean(raw_value).lower()
    if value not in {"true", "false"}:
        raise ValueError(f"row {row_number} field {field}: expected true or false")
    return value == "true"


def _exploit(row_number: int, raw_value: str) -> str:
    value = _clean(raw_value).lower()
    if value not in EXPLOIT_AVAILABLE_VALUES:
        raise ValueError(
            f"row {row_number} field exploit_available: expected none|poc|weaponized, got {value!r}"
        )
    return value


def _persona_float(hostname: str, field: str, raw_value: Any) -> float:
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"persona {hostname}: {field} must be numeric") from exc
    if field == "persona_risk" and not 0.0 <= value <= 1.0:
        raise ValueError(f"persona {hostname}: persona_risk must be 0-1")
    if field == "legacy_multiplier" and value <= 0.0:
        raise ValueError(f"persona {hostname}: legacy_multiplier must be positive")
    return value


if __name__ == "__main__":
    main()
