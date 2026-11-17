
from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True)
class RiskAssessment:
    likelihood: int | None
    impact: int | None
    score: int | None
    level: RiskLevel
    rationale: str


def assess_risk(
    likelihood: int | None,
    impact: int | None,
    rationale: str,
) -> RiskAssessment:
    """Calculate risk from explicit integer likelihood and impact ratings.

    Likelihood and impact use a 1-5 scale.
    If either rating is missing, risk is not assessed.
    """

    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("A risk assessment rationale is required.")

    for name, rating in (
        ("Likelihood", likelihood),
        ("Impact", impact),
    ):
        if rating is None:
            continue

        # Reject booleans and non-integer numeric values.
        if type(rating) is not int:
            raise ValueError(f"{name} must be an integer between 1 and 5.")

        if not 1 <= rating <= 5:
            raise ValueError(f"{name} must be between 1 and 5.")

    if likelihood is None or impact is None:
        return RiskAssessment(
            likelihood=likelihood,
            impact=impact,
            score=None,
            level=RiskLevel.NOT_ASSESSED,
            rationale=rationale,
        )

    score = likelihood * impact

    if score >= 20:
        level = RiskLevel.CRITICAL
    elif score >= 15:
        level = RiskLevel.HIGH
    elif score >= 8:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return RiskAssessment(
        likelihood=likelihood,
        impact=impact,
        score=score,
        level=level,
        rationale=rationale,
    )
