from __future__ import annotations

from backend.app.schemas.risk import RiskAssessment, RiskContribution
from backend.app.services.message_signal_detector import (
    MessageSignal,
)


SIGNAL_POINTS = {
    "payment_request": 35,
    "sensitive_credential_request": 45,
    "identity_document_request": 25,
    "pressure_or_urgency": 15,
    "external_contact_redirection": 10,
    "suspicious_recruitment_claim": 20,
}


def _category_for_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def evaluate_message_risk(
    signals: list[MessageSignal],
) -> RiskAssessment:
    if not signals:
        return RiskAssessment(
            risk_category="low",
            risk_score=0,
            confidence="low",
            contributions=[],
            rationale=(
                "No predefined suspicious message indicators were identified. "
                "This does not prove that the message is legitimate."
            ),
        )

    contributions: list[RiskContribution] = []
    score = 0

    for signal in signals:
        points = SIGNAL_POINTS.get(signal.signal, 0)

        if points <= 0:
            continue

        contributions.append(
            RiskContribution(
                signal=signal.signal,
                points=points,
                explanation=signal.explanation,
            )
        )
        score += points

    score = min(score, 100)
    category = _category_for_score(score)

    if score >= 70:
        confidence = "high"
        rationale = (
            "Multiple high-impact suspicious indicators were identified. "
            "Do not share sensitive information or make payments without "
            "independent verification."
        )
    elif score >= 40:
        confidence = "high"
        rationale = (
            "The message contains meaningful risk indicators. "
            "Independent verification is strongly recommended."
        )
    elif score >= 20:
        confidence = "medium"
        rationale = (
    "The message contains some suspicious indicators. "
    "Additional verification is recommended because this assessment "
    "does not establish legitimacy."
)
    else:
        confidence = "low"
        rationale = (
            "Only limited suspicious indicators were identified. "
            "This does not establish legitimacy."
        )

    return RiskAssessment(
        risk_category=category,
        risk_score=score,
        confidence=confidence,
        contributions=contributions,
        rationale=rationale,
    )