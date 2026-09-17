from pydantic import ValidationError
import pytest

from backend.app.schemas.analysis import EmailAnalysisRequest


def test_email_request_accepts_valid_payload():
    request = EmailAnalysisRequest(
        subject="Interview Invitation",
        sender="recruiter@example.com",
        reply_to="hr@example.com",
        body="Your interview is scheduled for tomorrow.",
    )

    assert request.subject == "Interview Invitation"
    assert request.sender == "recruiter@example.com"
    assert request.reply_to == "hr@example.com"


def test_email_request_allows_optional_metadata_defaults():
    request = EmailAnalysisRequest(
        body="Please review the interview details carefully.",
    )

    assert request.subject == ""
    assert request.sender == ""
    assert request.reply_to == ""


def test_email_request_rejects_missing_body():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(
            subject="Interview",
            sender="recruiter@example.com",
        )


def test_email_request_rejects_short_body():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(body="Too short")


def test_email_request_rejects_oversized_body():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(body="A" * 30_001)


def test_email_request_rejects_oversized_subject():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(
            subject="A" * 501,
            body="This is a valid email body for testing.",
        )


def test_email_request_rejects_oversized_sender():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(
            sender="a" * 321,
            body="This is a valid email body for testing.",
        )


def test_email_request_rejects_oversized_reply_to():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(
            reply_to="a" * 321,
            body="This is a valid email body for testing.",
        )