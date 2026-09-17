from backend.app.services.message_risk_engine import (
    evaluate_message_risk,
)
from backend.app.services.message_signal_detector import (
    detect_message_signals,
)


def assess(message: str):
    signals = detect_message_signals(message)
    return evaluate_message_risk(signals)


def test_clean_message_has_zero_score() -> None:
    assessment = assess(
        "Your interview is scheduled for Monday at 11 AM."
    )

    assert assessment.risk_score == 0
    assert assessment.risk_category == "low"
    assert assessment.confidence == "low"
    assert assessment.contributions == []


def test_payment_request_adds_high_risk_points() -> None:
    assessment = assess(
        "Pay the registration fee before attending the interview."
    )

    assert assessment.risk_score == 35
    assert assessment.risk_category == "medium"
    assert any(
        item.signal == "payment_request"
        for item in assessment.contributions
    )


def test_credential_request_is_high_impact() -> None:
    assessment = assess(
        "Send your OTP and login credentials immediately."
    )

    assert assessment.risk_score >= 45
    assert assessment.risk_category in {"high", "critical"}


def test_multiple_signals_reach_critical_category() -> None:
    assessment = assess(
        "Pay the registration fee, send your OTP and Aadhaar urgently."
    )

    assert assessment.risk_score >= 70
    assert assessment.risk_category == "critical"
    assert assessment.confidence == "high"


def test_score_is_capped_at_100() -> None:
    assessment = assess(
        "Pay the registration fee, send OTP, password, Aadhaar, "
        "PAN card, bank details urgently on Telegram for a guaranteed job."
    )

    assert assessment.risk_score <= 100


def test_urgency_alone_has_limited_impact() -> None:
    assessment = assess(
        "Urgent: respond now to confirm your interview."
    )

    assert assessment.risk_score == 15
    assert assessment.risk_category == "low"


def test_external_contact_signal_is_detected_in_assessment() -> None:
    assessment = assess(
        "Contact me privately on Telegram for the next steps."
    )

    assert assessment.risk_score == 10
    assert assessment.risk_category == "low"


def test_unknown_signal_does_not_add_points() -> None:
    from backend.app.services.message_signal_detector import MessageSignal

    assessment = evaluate_message_risk(
        [
            MessageSignal(
                category="test",
                signal="unknown_signal",
                explanation="Test signal.",
                severity="medium",
            )
        ]
    )

    assert assessment.risk_score == 0
    assert assessment.contributions == []


def test_rationale_warns_against_assuming_legitimacy() -> None:
    assessment = assess(
        "No interview required. Guaranteed job with instant joining."
    )

    assert "legitimacy" in assessment.rationale.lower()