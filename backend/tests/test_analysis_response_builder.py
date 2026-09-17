from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.analysis_response_builder import (
    build_url_analysis_response,
)


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


def test_builder_creates_response_for_successful_fetch() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    assert response.analysis_type == "url"
    assert response.status == "completed"
    assert response.risk_category == "unknown"
    assert response.risk_score == 0
    assert "HTTP response" in response.summary

    signals = [item.signal for item in response.evidence]

    assert "normalized_url" in signals
    assert "response_received" in signals
    assert "content_type" in signals


def test_builder_creates_response_for_failed_fetch() -> None:
    response = build_url_analysis_response(
        build_failed_signals()
    )

    assert response.analysis_type == "url"
    assert response.status == "completed"
    assert response.risk_category == "unknown"
    assert response.risk_score == 0
    assert "insufficient evidence" in response.summary

    signals = [item.signal for item in response.evidence]

    assert "normalized_url" in signals
    assert "fetch_failed" in signals

    assert any(
        "independent trusted source" in action
        for action in response.recommended_actions
    )


def test_builder_includes_redirect_evidence() -> None:
    signals = build_successful_signals()
    signals.redirect_count = 2

    response = build_url_analysis_response(signals)

    evidence_signals = [
        item.signal for item in response.evidence
    ]

    assert "redirects" in evidence_signals