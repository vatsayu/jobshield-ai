from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_url_analysis_endpoint_accepts_valid_url() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "https://example.com/jobs/security-analyst"},
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
        json={"url": "not-a-valid-url"},
    )

    assert response.status_code == 422

    body = response.json()

    assert body["error"] == "VALIDATION_ERROR"
    assert body["message"] == "Request data failed validation."
    assert body["request_id"]


def test_url_analysis_endpoint_rejects_unsupported_scheme() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "ftp://example.com/file"},
    )

    assert response.status_code == 422

    body = response.json()

    assert body["error"] == "VALIDATION_ERROR"
    assert body["request_id"]


def test_validation_error_preserves_incoming_request_id() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        headers={"X-Request-ID": "validation-test-001"},
        json={"url": "invalid-url"},
    )

    assert response.status_code == 422
    assert response.headers["X-Request-ID"] == "validation-test-001"
    assert response.json()["request_id"] == "validation-test-001"


def test_url_analysis_endpoint_rejects_loopback_target() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 422
    assert "unsafe IP targets" in response.json()["detail"]


def test_url_analysis_endpoint_rejects_private_target() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://192.168.1.10"},
    )

    assert response.status_code == 422
    assert "unsafe IP targets" in response.json()["detail"]


def test_url_analysis_endpoint_rejects_cloud_metadata_target() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://169.254.169.254/latest"},
    )

    assert response.status_code == 422
    assert "unsafe IP targets" in response.json()["detail"]