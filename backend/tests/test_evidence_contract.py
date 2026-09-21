
from __future__ import annotations

import pytest

from backend.app.services.email_analysis_response_builder import (
    build_email_analysis_response,
)
from backend.app.services.message_analysis_response_builder import (
    build_message_analysis_response,
)


VALID_RISK_CATEGORIES = {
    "unknown",
    "low",
    "medium",
    "high",
    "critical",
}

VALID_EVIDENCE_STATUSES = {
    "detected",
    "verified",
    "unverified",
    "insufficient_evidence",
}

VALID_EVIDENCE_SOURCES = {
    "deterministic_analysis",
    "external_verification",
    "user_provided",
    "ai_analysis",
}


def assert_valid_evidence_contract(response) -> None:
    """Validate the shared evidence contract for an analysis response."""

    assert response.analysis_id
    assert response.analysis_type in {"message", "email"}
    assert response.status == "completed"

    assert response.risk_category in VALID_RISK_CATEGORIES
    assert 0 <= response.risk_score <= 100
    assert response.summary.strip()

    assert response.evidence
    assert response.recommended_actions

    for item in response.evidence:
        assert item.category.strip()
        assert item.signal.strip()
        assert item.explanation.strip()

        assert item.severity in VALID_RISK_CATEGORIES
        assert item.status in VALID_EVIDENCE_STATUSES
        assert item.source in VALID_EVIDENCE_SOURCES


def assert_unique_evidence_signals(response) -> None:
    """Ensure the response does not contain duplicate evidence signals."""

    signals = [
        item.signal
        for item in response.evidence
    ]

    assert len(signals) == len(set(signals))


def test_message_evidence_contract() -> None:
    response = build_message_analysis_response(
        "Congratulations. You have been selected for the role. "
        "Please pay ₹2,000 for registration before your interview."
    )

    assert_valid_evidence_contract(response)


def test_message_evidence_signals_are_unique() -> None:
    response = build_message_analysis_response(
        "Congratulations. You have been selected. "
        "Pay ₹2,000 for registration before your interview."
    )

    assert_unique_evidence_signals(response)


def test_message_clean_content_has_valid_contract() -> None:
    response = build_message_analysis_response(
        "Your interview is scheduled for Monday at 11 AM."
    )

    assert_valid_evidence_contract(response)
    assert_unique_evidence_signals(response)

    assert response.risk_score >= 0
    assert response.risk_category in VALID_RISK_CATEGORIES


def test_email_evidence_contract() -> None:
    response = build_email_analysis_response(
        subject="Interview Confirmation",
        sender="hr@company.example",
        reply_to="",
        body=(
            "Congratulations. You have been selected. "
            "Please pay the registration fee before attending "
            "the interview."
        ),
    )

    assert_valid_evidence_contract(response)


def test_email_evidence_signals_are_unique() -> None:
    response = build_email_analysis_response(
        subject="Interview Confirmation",
        sender="hr@company.example",
        reply_to="",
        body=(
            "Congratulations. You have been selected. "
            "Please pay the registration fee before attending "
            "the interview."
        ),
    )

    assert_unique_evidence_signals(response)


def test_email_clean_content_has_valid_contract() -> None:
    response = build_email_analysis_response(
        subject="Interview Schedule",
        sender="hr@company.example",
        reply_to="",
        body=(
            "Your interview is scheduled for Monday at 11 AM. "
            "Please review the interview details."
        ),
    )

    assert_valid_evidence_contract(response)
    assert_unique_evidence_signals(response)

    assert response.risk_score >= 0
    assert response.risk_category in VALID_RISK_CATEGORIES


@pytest.mark.parametrize(
    "message",
    [
        "Please pay the registration fee before the interview.",
        "Send your OTP to confirm your job selection.",
        "Upload your Aadhaar and PAN card immediately.",
    ],
)
def test_message_security_indicators_have_evidence(
    message: str,
) -> None:
    response = build_message_analysis_response(message)

    assert_valid_evidence_contract(response)
    assert_unique_evidence_signals(response)

    assert len(response.evidence) >= 2


@pytest.mark.parametrize(
    "body",
    [
        "Please pay the registration fee before the interview.",
        "Send your OTP to confirm your job selection.",
        "Upload your Aadhaar and PAN card immediately.",
    ],
)
def test_email_security_indicators_have_evidence(
    body: str,
) -> None:
    response = build_email_analysis_response(
        subject="Important Recruitment Update",
        sender="hr@company.example",
        reply_to="",
        body=body,
    )

    assert_valid_evidence_contract(response)
    assert_unique_evidence_signals(response)

    assert len(response.evidence) >= 2