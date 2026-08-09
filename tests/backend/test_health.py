from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app


def test_application_starts() -> None:
    app = create_app(Settings(environment="test", log_level="INFO"))

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200


def test_health_endpoint_returns_structured_response() -> None:
    app = create_app(Settings(environment="test", app_name="Igris Test"))

    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "Igris Test",
        "version": "0.1.0",
        "environment": "test",
        "components": {"api": "ok"},
    }
    assert "X-Request-ID" in response.headers


def test_request_id_is_propagated_when_safe() -> None:
    app = create_app(Settings(environment="test"))

    with TestClient(app) as client:
        response = client.get("/api/v1/health", headers={"X-Request-ID": "req-test-123"})

    assert response.headers["X-Request-ID"] == "req-test-123"


def test_unsafe_request_id_is_replaced() -> None:
    app = create_app(Settings(environment="test"))

    with TestClient(app) as client:
        response = client.get("/api/v1/health", headers={"X-Request-ID": "bad\nvalue"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] != "bad\nvalue"
