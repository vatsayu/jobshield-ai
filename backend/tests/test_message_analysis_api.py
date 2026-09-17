from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_message_analysis_endpoint_accepts_valid_message() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": "Your interview is scheduled for Monday at 11 AM."
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["analysis_type"] == "message"
    assert body["status"] == "completed"
    assert body["analysis_id"]
    assert isinstance(body["risk_score"], int)
    assert "evidence" in body
    assert "recommended_actions" in body


def test_message_analysis_endpoint_detects_payment_request() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": (
                "Pay the registration fee before your interview."
            )
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["risk_score"] >= 35
    assert any(
        item["signal"] == "payment_request"
        for item in body["evidence"]
    )


def test_message_analysis_endpoint_detects_credential_request() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": "Send your OTP and password immediately."
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["risk_category"] in {"high", "critical"}


def test_message_analysis_endpoint_handles_clean_message() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": (
                "Your interview is scheduled for Monday at 11 AM."
            )
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["risk_score"] == 0
    assert body["risk_category"] == "low"


def test_message_analysis_endpoint_rejects_missing_message() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={},
    )

    assert response.status_code == 422

    body = response.json()

    assert body["error"] == "VALIDATION_ERROR"


def test_message_analysis_endpoint_rejects_short_message() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": "short"
        },
    )

    assert response.status_code == 422


def test_message_analysis_endpoint_rejects_oversized_message() -> None:
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": "A" * 20_001
        },
    )

    assert response.status_code == 422


def test_existing_url_endpoint_still_exists() -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={
            "url": "https://example.com"
        },
    )

    assert response.status_code in {202, 400, 422, 502}