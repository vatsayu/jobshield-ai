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
    assert body["status"] == "queued"
    assert body["risk_category"] == "unknown"
    assert body["risk_score"] == 0
    assert body["analysis_id"]


def test_url_analysis_endpoint_rejects_invalid_url() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "not-a-valid-url"},
    )

    assert response.status_code == 422


def test_url_analysis_endpoint_rejects_unsupported_scheme() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "ftp://example.com/file"},
    )

    assert response.status_code == 422