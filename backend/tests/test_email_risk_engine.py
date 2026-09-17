from backend.app.services.email_risk_engine import evaluate_email_risk
from backend.app.services.email_signal_detector import EmailSignal


def make_signal(signal: str, severity: str = "medium") -> EmailSignal:
    return EmailSignal(
        category="test",
        signal=signal,
        explanation=f"Test explanation for {signal}.",
        severity=severity,
    )


def test_empty_signals_return_low_risk():
    result = evaluate_email_risk([])

    assert result.risk_category == "low"
    assert result.risk_score == 0
    assert result.confidence == "low"
    assert result.contributions == []


def test_payment_request_scores_35():
    result = evaluate_email_risk(
        [make_signal("payment_request", "high")]
    )

    assert result.risk_score == 35
    assert result.risk_category == "medium"


def test_credential_request_scores_45():
    result = evaluate_email_risk(
        [make_signal("sensitive_credential_request", "critical")]
    )

    assert result.risk_score == 45
    assert result.risk_category == "high"


def test_multiple_signals_are_combined():
    result = evaluate_email_risk(
        [
            make_signal("payment_request", "high"),
            make_signal("pressure_or_urgency", "medium"),
        ]
    )

    assert result.risk_score == 50
    assert result.risk_category == "high"
    assert len(result.contributions) == 2


def test_score_is_capped_at_100():
    result = evaluate_email_risk(
        [
            make_signal("sensitive_credential_request", "critical"),
            make_signal("payment_request", "high"),
            make_signal("suspicious_attachment_instruction", "high"),
            make_signal("sender_reply_to_domain_mismatch", "high"),
        ]
    )

    assert result.risk_score == 100
    assert result.risk_category == "critical"


def test_medium_category_boundary():
    result = evaluate_email_risk(
        [
            make_signal("pressure_or_urgency", "medium"),
            make_signal("recruitment_keyword_domain", "medium"),
        ]
    )

    assert result.risk_score == 25
    assert result.risk_category == "medium"


def test_unknown_signal_does_not_add_points():
    result = evaluate_email_risk(
        [make_signal("unknown_signal")]
    )

    assert result.risk_score == 0
    assert result.risk_category == "low"
    assert result.contributions == []


def test_critical_rationale_for_high_score():
    result = evaluate_email_risk(
        [
            make_signal("sensitive_credential_request", "critical"),
            make_signal("payment_request", "high"),
        ]
    )

    assert result.risk_category == "critical"
    assert "Do not share sensitive information" in result.rationale