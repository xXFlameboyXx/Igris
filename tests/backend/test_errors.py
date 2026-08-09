from fastapi import APIRouter
from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app


def test_unknown_route_returns_structured_error() -> None:
    app = create_app(Settings(environment="test"))

    with TestClient(app) as client:
        response = client.get("/missing", headers={"X-Request-ID": "req-404"})

    assert response.status_code == 404
    assert response.json() == {
        "success": False,
        "error": {
            "code": "not_found",
            "message": "Not Found",
        },
        "request_id": "req-404",
    }


def test_validation_errors_are_structured() -> None:
    app = create_app(Settings(environment="test"))
    router = APIRouter()

    @router.get("/probe/{item_id}")
    async def probe(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    app.include_router(router)

    with TestClient(app) as client:
        response = client.get("/probe/not-an-int", headers={"X-Request-ID": "req-422"})

    payload = response.json()
    assert response.status_code == 422
    assert payload["success"] is False
    assert payload["error"]["code"] == "validation_error"
    assert payload["request_id"] == "req-422"
    assert payload["error"]["details"][0]["loc"] == ["path", "item_id"]

