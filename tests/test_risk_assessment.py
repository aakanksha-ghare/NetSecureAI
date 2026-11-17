
import pytest

from app.models.risk_assessment import (
    RiskLevel,
    assess_risk,
)


def test_low_risk_score() -> None:
    result = assess_risk(1, 5, "Low likelihood with limited impact.")

    assert result.score == 5
    assert result.level == RiskLevel.LOW


def test_medium_risk_score() -> None:
    result = assess_risk(2, 4, "Moderate potential business impact.")

    assert result.score == 8
    assert result.level == RiskLevel.MEDIUM


def test_high_risk_score() -> None:
    result = assess_risk(3, 5, "Likely event with major impact.")

    assert result.score == 15
    assert result.level == RiskLevel.HIGH


def test_critical_risk_score() -> None:
    result = assess_risk(4, 5, "High likelihood and severe impact.")

    assert result.score == 20
    assert result.level == RiskLevel.CRITICAL


def test_missing_rating_is_not_assessed() -> None:
    result = assess_risk(
        None,
        5,
        "Likelihood has not yet been assessed.",
    )

    assert result.score is None
    assert result.level == RiskLevel.NOT_ASSESSED


def test_missing_both_ratings_is_not_assessed() -> None:
    result = assess_risk(
        None,
        None,
        "Risk ratings have not yet been assessed.",
    )

    assert result.score is None
    assert result.level == RiskLevel.NOT_ASSESSED


@pytest.mark.parametrize(
    ("likelihood", "impact"),
    [
        (True, 3),
        (3, False),
        (2.5, 3),
        (3, 2.5),
    ],
)
def test_non_integer_ratings_are_rejected(
    likelihood: int,
    impact: int,
) -> None:
    with pytest.raises(ValueError):
        assess_risk(likelihood, impact, "Invalid rating type.")


def test_likelihood_outside_range_is_rejected() -> None:
    with pytest.raises(ValueError):
        assess_risk(6, 3, "Invalid likelihood.")


def test_impact_outside_range_is_rejected() -> None:
    with pytest.raises(ValueError):
        assess_risk(3, 0, "Invalid impact.")


def test_empty_rationale_is_rejected() -> None:
    with pytest.raises(ValueError):
        assess_risk(3, 4, "   ")


def test_non_string_rationale_is_rejected() -> None:
    with pytest.raises(ValueError):
        assess_risk(3, 4, None)  # type: ignore[arg-type]
