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
        normalized_url=(
            "https://unreachable-example.com/jobs"
        ),
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
        fetch_error=(
            "Unable to resolve the URL hostname."
        ),
        domain_age_days=None,
        suspicious_keywords=[],
    )


def test_builder_creates_response_for_successful_fetch() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    assert response.analysis_type == "url"
    assert response.status == "completed"
    assert response.risk_category == "low"
    assert response.risk_score == 0
    assert "technically reachable" in response.summary
    assert "deterministic risk indicators" in response.summary

    signals = [
        item.signal for item in response.evidence
    ]

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

    signals = [
        item.signal for item in response.evidence
    ]

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


def test_builder_includes_deterministic_risk_evidence() -> None:
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

    assert response.risk_score > 0
    assert response.risk_category in {
        "medium",
        "high",
        "critical",
    }

    evidence_signals = [
        item.signal for item in response.evidence
    ]

    assert "missing_https" in evidence_signals
    assert "non_standard_port" in evidence_signals
    assert "multiple_redirects" in evidence_signals
    assert "server_error_response" in evidence_signals


def test_builder_includes_https_evidence() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    evidence = {
        item.signal: item
        for item in response.evidence
    }

    assert "https_enabled" in evidence
    assert (
        evidence["https_enabled"].category
        == "transport_security"
    )
    assert (
        evidence["https_enabled"].severity
        == "unknown"
    )


def test_builder_includes_missing_https_evidence() -> None:
    signals = build_successful_signals()
    signals.normalized_url = "http://example.com/jobs"
    signals.scheme = "http"
    signals.has_https = False

    response = build_url_analysis_response(signals)

    evidence = {
        item.signal: item
        for item in response.evidence
    }

    assert "https_missing" in evidence
    assert (
        evidence["https_missing"].category
        == "transport_security"
    )
    assert (
        evidence["https_missing"].severity
        == "medium"
    )


def test_builder_includes_non_standard_port_evidence() -> None:
    signals = build_successful_signals()
    signals.port = 8080

    response = build_url_analysis_response(signals)

    evidence_signals = [
        item.signal for item in response.evidence
    ]

    assert "non_standard_port" in evidence_signals


def test_builder_includes_successful_http_status_evidence() -> None:
    response = build_url_analysis_response(
        build_successful_signals()
    )

    evidence = {
        item.signal: item
        for item in response.evidence
    }

    assert "successful_http_response" in evidence
    assert (
        evidence["successful_http_response"].category
        == "http_response"
    )
    assert (
        evidence["successful_http_response"].severity
        == "unknown"
    )


def test_builder_includes_client_error_evidence() -> None:
    signals = build_successful_signals()
    signals.status_code = 404

    response = build_url_analysis_response(signals)

    matching_evidence = [
        item
        for item in response.evidence
        if item.signal == "client_error_response"
    ]

    assert matching_evidence
    assert any(
        item.category == "http_response"
        for item in matching_evidence
    )
    assert any(
        item.severity == "medium"
        for item in matching_evidence
    )


def test_builder_includes_server_error_evidence() -> None:
    signals = build_successful_signals()
    signals.status_code = 503

    response = build_url_analysis_response(signals)

    matching_evidence = [
        item
        for item in response.evidence
        if item.signal == "server_error_response"
    ]

    assert matching_evidence
    assert any(
        item.category == "http_response"
        for item in matching_evidence
    )
    assert any(
        item.severity == "high"
        for item in matching_evidence
    )