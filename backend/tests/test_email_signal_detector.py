from backend.app.services.email_signal_detector import detect_email_signals


def signal_names(subject="", sender="", reply_to="", body=""):
    signals = detect_email_signals(
        subject=subject,
        sender=sender,
        reply_to=reply_to,
        body=body,
    )
    return {signal.signal for signal in signals}


def test_detects_payment_request():
    assert "payment_request" in signal_names(
        body="Please pay the registration fee before your interview."
    )


def test_detects_sensitive_credential_request():
    assert "sensitive_credential_request" in signal_names(
        body="Send your OTP and bank details for verification."
    )


def test_detects_identity_document_request():
    assert "identity_document_request" in signal_names(
        body="Submit your Aadhaar and PAN card."
    )


def test_detects_urgency():
    assert "pressure_or_urgency" in signal_names(
        subject="Urgent response required",
        body="Respond now or the offer expires.",
    )


def test_detects_external_contact_redirection():
    assert "external_contact_redirection" in signal_names(
        body="Contact me privately on Telegram."
    )


def test_detects_suspicious_recruitment_claim():
    assert "suspicious_recruitment_claim" in signal_names(
        body="Guaranteed job with no interview."
    )


def test_detects_attachment_instruction():
    assert "suspicious_attachment_instruction" in signal_names(
        body="Open the attachment and enable macros."
    )


def test_detects_sender_reply_to_mismatch():
    assert "sender_reply_to_domain_mismatch" in signal_names(
        sender="hr@company.com",
        reply_to="contact@gmail.com",
        body="Please review the interview details.",
    )


def test_detects_free_email_sender():
    assert "free_email_sender" in signal_names(
        sender="recruiter@gmail.com",
        body="Please review the interview details.",
    )


def test_detects_recruitment_keyword_domain():
    assert "recruitment_keyword_domain" in signal_names(
        sender="hr@careers-example.com",
        body="Please review the interview details.",
    )


def test_clean_email_has_no_content_signals():
    names = signal_names(
        sender="security@trustedcompany.example",
        body="Thank you for applying. Your interview is scheduled for Monday.",
    )

    assert names == set()