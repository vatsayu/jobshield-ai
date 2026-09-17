from backend.app.services.message_signal_detector import (
    detect_message_signals,
)


def signals_by_name(message: str) -> set[str]:
    return {
        signal.signal
        for signal in detect_message_signals(message)
    }


def test_detects_payment_request() -> None:
    signals = signals_by_name(
        "You must pay a registration fee before the interview."
    )

    assert "payment_request" in signals


def test_detects_credential_request() -> None:
    signals = signals_by_name(
        "Send your OTP and login credentials for verification."
    )

    assert "sensitive_credential_request" in signals


def test_detects_identity_document_request() -> None:
    signals = signals_by_name(
        "Please send your Aadhaar and PAN card immediately."
    )

    assert "identity_document_request" in signals


def test_detects_urgency_language() -> None:
    signals = signals_by_name(
        "Act now. This offer expires today only."
    )

    assert "pressure_or_urgency" in signals


def test_detects_external_contact_redirection() -> None:
    signals = signals_by_name(
        "Contact me privately on Telegram using my personal number."
    )

    assert "external_contact_redirection" in signals


def test_detects_suspicious_recruitment_claim() -> None:
    signals = signals_by_name(
        "Guaranteed job with instant joining and no interview."
    )

    assert "suspicious_recruitment_claim" in signals


def test_clean_message_has_no_signals() -> None:
    signals = detect_message_signals(
        "Your interview is scheduled for Monday at 11 AM. "
        "Please bring a copy of your resume."
    )

    assert signals == []


def test_detection_is_case_insensitive() -> None:
    signals = signals_by_name(
        "URGENT: PAY THE PROCESSING FEE NOW."
    )

    assert "payment_request" in signals
    assert "pressure_or_urgency" in signals


def test_multiple_categories_are_detected() -> None:
    signals = signals_by_name(
        "Pay the registration fee and send your Aadhaar on WhatsApp urgently."
    )

    assert {
        "payment_request",
        "identity_document_request",
        "pressure_or_urgency",
        "external_contact_redirection",
    }.issubset(signals)


def test_detector_does_not_classify_message_as_fraud() -> None:
    signals = detect_message_signals(
        "Please send your resume and attend the interview."
    )

    assert all(signal.signal != "fraud_confirmed" for signal in signals)