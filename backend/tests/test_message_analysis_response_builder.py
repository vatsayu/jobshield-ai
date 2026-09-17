from backend.app.services.message_analysis_response_builder import (
    build_message_analysis_response,
)


def evidence_signals(message: str) -> set[str]:
    response = build_message_analysis_response(message)

    return {item.signal for item in response.evidence}


def test_builder_returns_message_analysis_response() -> None:
    response = build_message_analysis_response(
        "Your interview is scheduled for Monday at 11 AM."
    )

    assert response.analysis_type == "message"
    assert response.status == "completed"
    assert response.analysis_id
    assert isinstance(response.risk_score, int)


def test_builder_includes_message_processed_evidence() -> None:
    signals = evidence_signals(
        "Your interview is scheduled for Monday at 11 AM."
    )

    assert "message_processed" in signals


def test_builder_includes_payment_evidence() -> None:
    signals = evidence_signals(
        "Pay the registration fee before the interview."
    )

    assert "payment_request" in signals


def test_builder_includes_credential_evidence() -> None:
    signals = evidence_signals(
        "Send your OTP and password immediately."
    )

    assert "sensitive_credential_request" in signals


def test_builder_includes_document_evidence() -> None:
    signals = evidence_signals(
        "Send your Aadhaar and PAN card."
    )

    assert "identity_document_request" in signals


def test_builder_includes_deterministic_risk_evidence() -> None:
    response = build_message_analysis_response(
        "Pay the registration fee urgently."
    )

    assert any(
        item.category == "deterministic_risk"
        for item in response.evidence
    )


def test_clean_message_has_low_risk() -> None:
    response = build_message_analysis_response(
        "Your interview is scheduled for Monday at 11 AM."
    )

    assert response.risk_category == "low"
    assert response.risk_score == 0
    assert "legitimate" in response.summary.lower()


def test_suspicious_message_has_recommendations() -> None:
    response = build_message_analysis_response(
        "Pay the registration fee and send your OTP urgently."
    )

    assert response.risk_score >= 70
    assert len(response.recommended_actions) >= 3
    assert any(
        "OTP" in action
        for action in response.recommended_actions
    )


def test_summary_does_not_claim_confirmed_fraud() -> None:
    response = build_message_analysis_response(
        "Guaranteed job with instant joining."
    )

    assert "prove fraud" in response.summary.lower()


def test_all_evidence_has_required_fields() -> None:
    response = build_message_analysis_response(
        "Contact me privately on Telegram and pay the processing fee."
    )

    for item in response.evidence:
        assert item.category
        assert item.signal
        assert item.explanation
        assert item.severity