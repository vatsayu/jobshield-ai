from __future__ import annotations

from backend.app.schemas.risk import RiskAssessment, RiskContribution
from backend.app.services.email_signal_detector import EmailSignal


SIGNAL_POINTS = {
    "sensitive_credential_request": 45,
    "payment_request": 35,
    "suspicious_attachment_instruction": 30,
    "sender_reply_to_domain_mismatch": 30,
    "identity_document_request": 25,
    "suspicious_recruitment_claim": 20,
    "pressure_or_urgency": 15,
    "recruitment_keyword_domain": 10,
    "external_contact_redirection": 10,
    "free_email_sender": 5,
}


def _category_for_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def evaluate_email_risk(
    signals: list[EmailSignal],
) -> RiskAssessment:
    if not signals:
        return RiskAssessment(
            risk_category="low",
            risk_score=0,
            confidence="low",
            contributions=[],
            rationale=(
                "No predefined suspicious email indicators were identified. "
                "This does not prove that the email or sender is legitimate."
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
            "Multiple high-impact email risk indicators were identified. "
            "Do not share sensitive information, open suspicious attachments, "
            "or make payments without independent verification."
        )
    elif score >= 40:
        confidence = "high"
        rationale = (
            "The email contains meaningful security risk indicators. "
            "Independent verification is strongly recommended."
        )
    elif score >= 20:
        confidence = "medium"
        rationale = (
            "The email contains some suspicious indicators. "
            "Additional verification is recommended because this assessment "
            "does not establish fraud."
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