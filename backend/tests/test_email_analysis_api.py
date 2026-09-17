from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_email_analysis_endpoint_accepts_valid_email():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "subject": "Interview Invitation",
            "sender": "hr@company.example",
            "reply_to": "",
            "body": "Thank you for applying. Your interview is scheduled for Monday.",
        },
    )

    assert response.status_code == 202

    data = response.json()
    assert data["analysis_type"] == "email"
    assert data["status"] == "completed"
    assert "risk_score" in data
    assert "evidence" in data
    assert "recommended_actions" in data


def test_email_endpoint_detects_payment_request():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "sender": "hr@company.example",
            "body": "Please pay the registration fee before the interview.",
        },
    )

    assert response.status_code == 202

    data = response.json()
    assert data["risk_score"] == 35
    assert any(
        item["signal"] == "payment_request"
        for item in data["evidence"]
    )


def test_email_endpoint_detects_credential_request():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "sender": "hr@company.example",
            "body": "Send your OTP and bank details immediately.",
        },
    )

    assert response.status_code == 202

    data = response.json()
    assert data["risk_category"] == "high"
    assert any(
        item["signal"] == "sensitive_credential_request"
        for item in data["evidence"]
    )


def test_email_endpoint_detects_sender_reply_to_mismatch():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "sender": "recruiter@company.example",
            "reply_to": "random@gmail.com",
            "body": "Please review the interview details carefully.",
        },
    )

    assert response.status_code == 202

    data = response.json()
    assert any(
        item["signal"] == "sender_reply_to_domain_mismatch"
        for item in data["evidence"]
    )


def test_email_endpoint_rejects_missing_body():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "subject": "Interview",
            "sender": "hr@company.example",
        },
    )

    assert response.status_code == 422


def test_email_endpoint_rejects_short_body():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "body": "Too short",
        },
    )

    assert response.status_code == 422


def test_email_endpoint_rejects_oversized_body():
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "body": "A" * 30_001,
        },
    )

    assert response.status_code == 422


def test_existing_analysis_endpoints_remain_available():
    response = client.post(
        "/api/v1/analyze/message",
        json={
            "message": "Please review the interview details carefully.",
        },
    )

    assert response.status_code == 202