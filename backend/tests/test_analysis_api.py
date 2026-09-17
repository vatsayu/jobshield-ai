from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.signals import URLTechnicalSignals


client = TestClient(app)


def test_url_analysis_endpoint_accepts_valid_url() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "https://example.com/jobs/security-analyst"
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["analysis_type"] == "url"
    assert body["status"] == "completed"
    assert body["risk_category"] == "unknown"
    assert body["risk_score"] == 0
    assert body["analysis_id"]
    assert body["summary"]
    assert body["evidence"]
    assert body["evidence"][0]["signal"] == "normalized_url"


def test_url_analysis_endpoint_rejects_invalid_url() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "not-a-valid-url"
        },
    )

    assert response.status_code == 422

    body = response.json()

    assert body["error"] == "VALIDATION_ERROR"
    assert body["message"] == (
        "Request data failed validation."
    )
    assert body["request_id"]


def test_url_analysis_endpoint_rejects_unsupported_scheme() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "ftp://example.com/file"
        },
    )

    assert response.status_code == 422

    body = response.json()

    assert body["error"] == "VALIDATION_ERROR"
    assert body["request_id"]


def test_validation_error_preserves_incoming_request_id() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        headers={
            "X-Request-ID": "validation-test-001"
        },
        json={
            "url": "invalid-url"
        },
    )

    assert response.status_code == 422
    assert response.headers["X-Request-ID"] == (
        "validation-test-001"
    )
    assert response.json()["request_id"] == (
        "validation-test-001"
    )


def test_url_analysis_endpoint_rejects_loopback_target() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "http://127.0.0.1:8000"
        },
    )

    assert response.status_code == 422
    assert "unsafe IP targets" in (
        response.json()["detail"]
    )


def test_url_analysis_endpoint_rejects_private_target() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "http://192.168.1.10"
        },
    )

    assert response.status_code == 422
    assert "unsafe IP targets" in (
        response.json()["detail"]
    )


def test_url_analysis_endpoint_rejects_cloud_metadata_target() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "http://169.254.169.254/latest"
        },
    )

    assert response.status_code == 422
    assert "unsafe IP targets" in (
        response.json()["detail"]
    )


def test_url_analysis_endpoint_returns_fetch_success_evidence() -> None:
    signals = URLTechnicalSignals(
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

    with patch(
        "backend.app.api.v1.analyze.url_analyzer.analyze",
        return_value=signals,
    ):
        response = client.post(
            "/api/v1/analyze/url",
            json={
                "url": "https://example.com/jobs"
            },
        )

    assert response.status_code == 202

    body = response.json()

    assert body["analysis_type"] == "url"
    assert body["status"] == "completed"
    assert body["risk_category"] == "unknown"
    assert body["risk_score"] == 0
    assert body["summary"]

    evidence_signals = [
        item["signal"]
        for item in body["evidence"]
    ]

    assert "normalized_url" in evidence_signals
    assert "response_received" in evidence_signals
    assert "content_type" in evidence_signals


def test_url_analysis_endpoint_returns_fetch_failure_evidence() -> None:
    signals = URLTechnicalSignals(
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

    with patch(
        "backend.app.api.v1.analyze.url_analyzer.analyze",
        return_value=signals,
    ):
        response = client.post(
            "/api/v1/analyze/url",
            json={
                "url": (
                    "https://unreachable-example.com/jobs"
                )
            },
        )

    assert response.status_code == 202

    body = response.json()

    assert body["analysis_type"] == "url"
    assert body["status"] == "completed"
    assert body["risk_category"] == "unknown"
    assert body["risk_score"] == 0
    assert "insufficient evidence" in body["summary"]

    evidence_signals = [
        item["signal"]
        for item in body["evidence"]
    ]

    assert "normalized_url" in evidence_signals
    assert "fetch_failed" in evidence_signals


def test_url_analysis_endpoint_returns_redirect_evidence() -> None:
    signals = URLTechnicalSignals(
        normalized_url="https://example.com/jobs",
        hostname="example.com",
        scheme="https",
        port=None,
        has_https=True,
        redirect_count=2,
        final_url="https://www.example.com/jobs",
        status_code=200,
        content_type="text/html",
        content_length=256,
        response_size_bytes=256,
        fetch_status="success",
        fetch_error=None,
        domain_age_days=None,
        suspicious_keywords=[],
    )

    with patch(
        "backend.app.api.v1.analyze.url_analyzer.analyze",
        return_value=signals,
    ):
        response = client.post(
            "/api/v1/analyze/url",
            json={
                "url": "https://example.com/jobs"
            },
        )

    assert response.status_code == 202

    body = response.json()

    evidence_signals = [
        item["signal"]
        for item in body["evidence"]
    ]

    assert "redirects" in evidence_signals