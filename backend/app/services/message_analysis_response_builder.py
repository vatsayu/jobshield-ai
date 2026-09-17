from __future__ import annotations

from uuid import uuid4

from backend.app.schemas.analysis import (
    AnalysisResponse,
    EvidenceItem,
)
from backend.app.services.message_risk_engine import (
    evaluate_message_risk,
)
from backend.app.services.message_signal_detector import (
    MessageSignal,
    detect_message_signals,
)


def _signal_to_evidence(signal: MessageSignal) -> EvidenceItem:
    return EvidenceItem(
        category=signal.category,
        signal=signal.signal,
        explanation=signal.explanation,
        severity=signal.severity,
    )


def build_message_analysis_response(
    message: str,
) -> AnalysisResponse:
    signals = detect_message_signals(message)
    risk_assessment = evaluate_message_risk(signals)

    evidence: list[EvidenceItem] = [
        EvidenceItem(
            category="message_analysis",
            signal="message_processed",
            explanation=(
                "The recruitment message was analyzed using deterministic "
                "security-relevant text indicators."
            ),
            severity="unknown",
        )
    ]

    evidence.extend(
        _signal_to_evidence(signal)
        for signal in signals
    )
    # Risk contributions are already represented by the detected signal
    # evidence above. Do not append them again, otherwise the UI displays
    # duplicate evidence items.

    if signals:
        summary = (
            "The message contains one or more security-relevant indicators. "
            "These indicators require further verification and do not by "
            "themselves prove fraud."
        )
    else:
        summary = (
            "No predefined suspicious indicators were identified in the "
            "message. This does not prove that the sender or opportunity "
            "is legitimate."
        )

    recommended_actions = [
        "Verify the recruiter and employer through independent trusted sources.",
        "Do not share OTPs, passwords, PINs, or banking credentials.",
        "Do not pay recruitment, registration, processing, or training fees.",
    ]

    if signals:
        recommended_actions.append(
            "Review each detected indicator before continuing the conversation."
        )

    return AnalysisResponse(
        analysis_id=str(uuid4()),
        analysis_type="message",
        status="completed",
        risk_category=risk_assessment.risk_category,
        risk_score=risk_assessment.risk_score,
        summary=summary,
        evidence=evidence,
        recommended_actions=recommended_actions,
    )