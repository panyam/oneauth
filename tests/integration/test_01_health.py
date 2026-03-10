"""Health check endpoint."""


def test_health_returns_ok(client):
    r = client.get("/_ah/health")
    assert r.status_code == 200
    assert r.text == "ok"
