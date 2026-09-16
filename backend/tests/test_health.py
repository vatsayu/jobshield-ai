from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "JobShield AI API",
        "version": "0.1.0",
        "environment": "development",
    }


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "service": "JobShield AI API",
        "version": "0.1.0",
        "status": "ok",
    }


def test_info_endpoint() -> None:
    response = client.get("/api/v1/info")

    assert response.status_code == 200
    assert response.json() == {
        "name": "JobShield AI API",
        "version": "0.1.0",
        "environment": "development",
        "description": (
            "AI-assisted security analysis platform for "
            "job postings and recruitment communications."
        ),
    }