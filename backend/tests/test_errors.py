from fastapi.testclient import TestClient

from backend.app.core.exceptions import InvalidInputException
from backend.app.main import app


client = TestClient(app)


def test_invalid_input_exception_structure() -> None:
    exception = InvalidInputException("Test invalid input")

    assert exception.error_code == "INVALID_INPUT"
    assert exception.message == "Test invalid input"


def test_health_endpoint_still_works() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "JobShield AI API",
        "version": "0.1.0",
        "environment": "development",
    }