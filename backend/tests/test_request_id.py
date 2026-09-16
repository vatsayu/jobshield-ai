from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_request_id_is_generated() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers.get("X-Request-ID")
    assert len(response.headers["X-Request-ID"]) > 10


def test_request_id_is_preserved() -> None:
    request_id = "test-request-123"

    response = client.get(
        "/api/v1/health",
        headers={"X-Request-ID": request_id},
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id