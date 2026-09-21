
from __future__ import annotations

from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.analysis_response_builder import (
    build_url_analysis_response,
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


def build_successful_signals() -> URLTechnicalSignals:
    return URLTechnicalSignals(
        normalized_url="https://example.com/jobs",
        hostname="example.com",
        scheme="https",
        port=None,
        has_https=True,
        redirect_count=0,
        final_url="https://example.com/jobs",
        status_code=200,
        content_type="text/html",
        content_length=128,
        response_size_bytes=128,
        fetch_status="success",
        fetch_error=None,
        domain_age_days=None,
        suspicious_keywords=[],
    )


def build_failed_signals() -> URLTechnicalSignals:
    return URLTechnicalSignals(
        normalized_url="https://unreachable-example.com/jobs",
        hostname="unreachable-example.com",
        scheme="https",
        port=None,
        has_https=True,
        redirect_count=0,
        final_url=None,
        status_code=None,
        content_type=None,
        content_length=None,
        response_size_bytes=0,
        fetch_status="failed",
        fetch_error="Unable to resolve the URL hostname.",
        domain_age_days=None,
        suspicious_keywords=[],
    )


def assert_valid_url_evidence_contract(response) -> None:
    """Validate the shared evidence contract for URL analysis."""

    assert response.analysis_id
    assert response.analysis_type == "url"
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
    """Ensure URL evidence does not contain duplicate signal names."""

    signals = [
        item.signal
        for item in response.evidence
    ]

    assert len(signals) == len(set(signals))


def test_successful_url_evidence_contract() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    assert_valid_url_evidence_contract(response)


def test_failed_url_evidence_contract() -> None:
    response = build_url_analysis_response(
        build_failed_signals()
    )

    assert_valid_url_evidence_contract(response)


def test_successful_url_evidence_signals_are_unique() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    assert_unique_evidence_signals(response)


def test_failed_url_evidence_signals_are_unique() -> None:
    response = build_url_analysis_response(
        build_failed_signals()
    )

    assert_unique_evidence_signals(response)


def test_successful_url_contains_expected_evidence() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    evidence_signals = {
        item.signal
        for item in response.evidence
    }

    assert "normalized_url" in evidence_signals
    assert "https_enabled" in evidence_signals
    assert "successful_http_response" in evidence_signals
    assert "response_received" in evidence_signals
    assert "content_type" in evidence_signals


def test_failed_url_contains_fetch_failure_evidence() -> None:
    response = build_url_analysis_response(
        build_failed_signals()
    )

    evidence_signals = {
        item.signal
        for item in response.evidence
    }

    assert "normalized_url" in evidence_signals
    assert "fetch_failed" in evidence_signals


def test_successful_url_has_low_risk_without_indicators() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    assert response.risk_score == 0
    assert response.risk_category == "low"


def test_failed_url_has_unknown_risk_category() -> None:
    response = build_url_analysis_response(
        build_failed_signals()
    )

    assert response.risk_score == 0
    assert response.risk_category == "unknown"


def test_url_evidence_contains_metadata() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    for item in response.evidence:
        assert item.status == "detected"
        assert item.source == "deterministic_analysis"


def test_url_risk_evidence_has_expected_structure() -> None:
    signals = build_successful_signals()

    signals.normalized_url = (
        "http://secure-login.example.com:8080/payment"
    )
    signals.hostname = "secure-login.example.com"
    signals.scheme = "http"
    signals.port = 8080
    signals.has_https = False
    signals.redirect_count = 3
    signals.status_code = 503

    response = build_url_analysis_response(signals)

    assert_valid_url_evidence_contract(response)

    risk_evidence = [
        item
        for item in response.evidence
        if item.category == "deterministic_risk"
    ]

    assert risk_evidence

    for item in risk_evidence:
        assert item.signal.strip()
        assert item.explanation.strip()
        assert item.severity in {
            "medium",
            "high",
            "critical",
        }


def test_url_risk_score_stays_within_bounds() -> None:
    signals = build_successful_signals()

    signals.normalized_url = (
        "http://secure-login.example.com:8080/payment"
    )
    signals.hostname = "secure-login.example.com"
    signals.scheme = "http"
    signals.port = 8080
    signals.has_https = False
    signals.redirect_count = 3
    signals.status_code = 503
    signals.suspicious_keywords = [
        "login",
        "secure",
        "payment",
    ]

    response = build_url_analysis_response(signals)

    assert 0 <= response.risk_score <= 100


def test_url_missing_https_has_expected_evidence_metadata() -> None:
    signals = build_successful_signals()

    signals.normalized_url = "http://example.com/jobs"
    signals.scheme = "http"
    signals.has_https = False

    response = build_url_analysis_response(signals)

    matching_evidence = [
        item
        for item in response.evidence
        if item.signal == "https_missing"
    ]

    assert len(matching_evidence) == 1

    item = matching_evidence[0]

    assert item.category == "transport_security"
    assert item.severity == "medium"
    assert item.status == "detected"
    assert item.source == "deterministic_analysis"


def test_url_ip_address_has_expected_risk_evidence() -> None:
    signals = build_successful_signals()

    signals.hostname = "8.8.8.8"
    signals.normalized_url = "https://8.8.8.8/jobs"
    signals.final_url = signals.normalized_url

    response = build_url_analysis_response(signals)

    matching_evidence = [
        item
        for item in response.evidence
        if item.signal == "ip_address_hostname"
    ]

    assert len(matching_evidence) == 1

    item = matching_evidence[0]

    assert item.category == "deterministic_risk"
    assert item.severity == "high"
    assert item.status == "detected"
    assert item.source == "deterministic_analysis"


def test_url_redirect_evidence_has_valid_contract() -> None:
    signals = build_successful_signals()
    signals.redirect_count = 2

    response = build_url_analysis_response(signals)

    matching_evidence = [
        item
        for item in response.evidence
        if item.signal == "redirects"
    ]

    assert len(matching_evidence) == 1

    item = matching_evidence[0]

    assert item.category == "http_fetch"
    assert item.status == "detected"
    assert item.source == "deterministic_analysis"