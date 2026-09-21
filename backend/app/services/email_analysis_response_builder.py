
from __future__ import annotations

from uuid import uuid4

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EvidenceItem,
)
from backend.app.services.email_risk_engine import (
    evaluate_email_risk,
)
from backend.app.services.email_signal_detector import (
    EmailSignal,
    detect_email_signals,
)


def _signal_to_evidence(
    signal: EmailSignal,
) -> EvidenceItem:
    return EvidenceItem(
        category=signal.category,
        signal=signal.signal,
        explanation=signal.explanation,
        severity=signal.severity,
        status="detected",
        source="deterministic_analysis",
    )


def build_email_analysis_response(
    *,
    subject: str,
    sender: str,
    reply_to: str,
    body: str,
) -> AnalysisResponse:
    signals = detect_email_signals(
        subject=subject,
        sender=sender,
        reply_to=reply_to,
        body=body,
    )

    risk_assessment = evaluate_email_risk(signals)

    evidence: list[EvidenceItem] = [
        EvidenceItem(
            category="email_analysis",
            signal="email_processed",
            explanation=(
                "The email was analyzed using deterministic "
                "security-relevant content, sender, routing, "
                "and attachment indicators."
            ),
            severity="unknown",
            status="detected",
            source="deterministic_analysis",
        )
    ]

    evidence.extend(
        _signal_to_evidence(signal)
        for signal in signals
    )

    # Track existing signals so that risk contributions do not
    # create duplicate evidence entries.
    existing_signals = {
        item.signal
        for item in evidence
    }

    # Add only unique risk contributions.
    # This preserves risk evidence that is not already represented
    # by a detected email signal.
    for contribution in risk_assessment.contributions:
        if contribution.signal in existing_signals:
            continue

        evidence.append(
            EvidenceItem(
                category="deterministic_risk",
                signal=contribution.signal,
                explanation=contribution.explanation,
                severity=(
                    "critical"
                    if contribution.points >= 45
                    else "high"
                    if contribution.points >= 25
                    else "medium"
                    if contribution.points >= 15
                    else "low"
                ),
                status="detected",
                source="deterministic_analysis",
            )
        )

        existing_signals.add(contribution.signal)

    if signals:
        summary = (
            "The email contains one or more security-relevant "
            "indicators. These indicators require further "
            "verification and do not by themselves prove fraud."
        )
    else:
        summary = (
            "No predefined suspicious indicators were identified "
            "in the email. This does not prove that the sender "
            "or opportunity is legitimate."
        )

    recommended_actions = [
        "Verify the sender and employer through independent trusted sources.",
        "Do not share OTPs, passwords, PINs, or banking credentials.",
        "Do not pay recruitment, registration, processing, or training fees.",
        "Do not open suspicious attachments or enable macros/content.",
    ]

    if signals:
        recommended_actions.append(
            "Review each detected indicator before continuing the conversation."
        )

    return AnalysisResponse(
        analysis_id=str(uuid4()),
        analysis_type="email",
        status="completed",
        risk_category=risk_assessment.risk_category,
        risk_score=risk_assessment.risk_score,
        summary=summary,
        evidence=evidence,
        recommended_actions=recommended_actions,
    )