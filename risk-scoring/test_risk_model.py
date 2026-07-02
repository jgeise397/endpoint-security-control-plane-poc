from __future__ import annotations

from pathlib import Path

import pytest

import risk_model


ROOT = Path(__file__).resolve().parent
SAMPLE_CSV = ROOT / "sample_vulnerabilities.csv"
PERSONAS = ROOT.parent / "endpoint-fleet" / "endpoint-personas.yaml"


def _scores_by_id() -> dict[str, risk_model.FindingScore]:
    return {
        score.finding.finding_id: score
        for score in risk_model.score_csv(SAMPLE_CSV, PERSONAS)
    }


def test_persona_factors_separate_identical_winrar_findings() -> None:
    scores = _scores_by_id()
    user_score = scores["F-001"]
    dev_score = scores["F-002"]

    assert dev_score.final_score > user_score.final_score
    assert dev_score.finding.cve == user_score.finding.cve == "CVE-2023-38831"

    changing_factors = {"criticality", "exposure", "persona_risk"}
    identical_vuln_factors = {
        "cvss",
        "epss",
        "kev",
        "exploit_available",
        "arcane_context",
    }

    for factor in changing_factors:
        assert (
            dev_score.factors[factor].contribution
            > user_score.factors[factor].contribution
        )

    for factor in identical_vuln_factors:
        assert dev_score.factors[factor].contribution == pytest.approx(
            user_score.factors[factor].contribution
        )


def test_legacy_multiplier_and_controls_are_visible_individual_effects(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "synthetic.csv"
    csv_path.write_text(
        "\n".join(
            [
                ",".join(risk_model.REQUIRED_COLUMNS),
                "L-001,win-user-01,CVE-2024-21338,8.8,0.03,false,none,0.20,user comparison row",
                "L-002,win-legacy-01,CVE-2024-21338,8.8,0.03,false,none,0.20,legacy comparison row",
            ]
        ),
        encoding="utf-8",
    )

    scores = {
        score.finding.finding_id: score
        for score in risk_model.score_csv(csv_path, PERSONAS)
    }
    user_score = scores["L-001"]
    legacy_score = scores["L-002"]

    assert legacy_score.score_after_legacy_multiplier > legacy_score.base_score
    assert legacy_score.score_after_legacy_multiplier > user_score.base_score
    assert legacy_score.total_control_subtraction > 0
    assert legacy_score.final_score == pytest.approx(
        legacy_score.score_after_legacy_multiplier
        - legacy_score.total_control_subtraction
    )
    assert set(legacy_score.control_subtractions) == {
        "network_isolation",
        "inbound_restriction",
        "rdp_disabled_default",
        "reduced_local_admin",
    }


def test_severity_is_not_priority_when_exploitation_context_is_stronger(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "priority.csv"
    csv_path.write_text(
        "\n".join(
            [
                ",".join(risk_model.REQUIRED_COLUMNS),
                "P-001,win-user-01,CVE-2024-3094,10.0,0.02,false,none,0.10,high severity low likelihood",
                "P-002,win-user-01,CVE-2023-38831,7.8,0.94,true,weaponized,0.90,lower severity active exploitation",
            ]
        ),
        encoding="utf-8",
    )

    scores = {
        score.finding.finding_id: score
        for score in risk_model.score_csv(csv_path, PERSONAS)
    }

    assert scores["P-002"].final_score > scores["P-001"].final_score


@pytest.mark.parametrize(
    ("row", "message_parts"),
    [
        (
            "V-001,win-user-01,CVE-TEST,10.1,0.1,false,none,0.1,note",
            ["row 2", "field cvss"],
        ),
        (
            "V-001,win-user-01,CVE-TEST,5.0,0.1,false,maybe,0.1,note",
            ["row 2", "field exploit_available"],
        ),
        (
            "V-001,no-such-host,CVE-TEST,5.0,0.1,false,none,0.1,note",
            ["row 2", "field endpoint"],
        ),
    ],
)
def test_validation_failures_name_row_and_field(
    tmp_path: Path, row: str, message_parts: list[str]
) -> None:
    csv_path = tmp_path / "bad.csv"
    csv_path.write_text(
        "\n".join([",".join(risk_model.REQUIRED_COLUMNS), row]),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        risk_model.score_csv(csv_path, PERSONAS)

    message = str(exc_info.value)
    for part in message_parts:
        assert part in message


def test_missing_column_names_header_row_and_field(tmp_path: Path) -> None:
    csv_path = tmp_path / "missing-column.csv"
    columns = [column for column in risk_model.REQUIRED_COLUMNS if column != "cvss"]
    csv_path.write_text(
        "\n".join(
            [
                ",".join(columns),
                "V-001,win-user-01,CVE-TEST,0.1,false,none,0.1,note",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"row 1.*field cvss"):
        risk_model.score_csv(csv_path, PERSONAS)


def test_rendered_markdown_is_deterministic() -> None:
    first = risk_model.render_markdown(risk_model.score_csv(SAMPLE_CSV, PERSONAS))
    second = risk_model.render_markdown(risk_model.score_csv(SAMPLE_CSV, PERSONAS))

    assert first == second


def test_scores_are_bounded() -> None:
    scores = risk_model.score_csv(SAMPLE_CSV, PERSONAS)

    assert all(0.0 <= score.final_score <= 100.0 for score in scores)
