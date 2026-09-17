from backend.app.services.email_analysis_response_builder import (
    build_email_analysis_response,
)


def test_clean_email_response():
    result = build_email_analysis_response(
        subject="Interview Invitation",
        sender="security@trustedcompany.example",
        reply_to="",
        body="Thank you for applying. Your interview is scheduled for Monday.",
    )

    assert result.analysis_type == "email"
    assert result.status == "completed"
    assert result.risk_score == 0
    assert result.risk_category == "low"
    assert result.analysis_id
    assert result.evidence[0].signal == "email_processed"


def test_payment_email_response():
    result = build_email_analysis_response(
        subject="Interview Confirmation",
        sender="hr@company.example",
        reply_to="",
        body="Please pay the registration fee before attending the interview.",
    )

    assert result.risk_score == 35
    assert result.risk_category == "medium"
    assert any(
        evidence.signal == "payment_request"
        for evidence in result.evidence
    )


def test_critical_email_response():
    result = build_email_analysis_response(
        subject="Immediate Verification",
        sender="hr@company.example",
        reply_to="contact@gmail.com",
        body="Send your OTP and bank details immediately.",
    )

    assert result.risk_category == "critical"
    assert result.risk_score >= 70
    assert any(
        evidence.signal == "sensitive_credential_request"
        for evidence in result.evidence
    )
    assert any(
        "Do not share OTPs" in action
        for action in result.recommended_actions
    )


def test_sender_reply_to_mismatch_is_included():
    result = build_email_analysis_response(
        subject="Interview",
        sender="recruiter@company.example",
        reply_to="random@gmail.com",
        body="Please review the interview details carefully.",
    )

    assert any(
        evidence.signal == "sender_reply_to_domain_mismatch"
        for evidence in result.evidence
    )


def test_recommendations_are_present():
    result = build_email_analysis_response(
        subject="Interview",
        sender="hr@company.example",
        reply_to="",
        body="Please review the interview details carefully.",
    )

    assert len(result.recommended_actions) >= 4