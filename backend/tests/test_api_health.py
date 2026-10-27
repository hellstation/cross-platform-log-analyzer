from fastapi.testclient import TestClient

from sentineltrace.api.app import create_app


def test_health_endpoint():
    client = TestClient(create_app())
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "version" in body
