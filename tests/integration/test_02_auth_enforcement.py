"""Admin auth enforcement — no key, wrong key, correct key."""


def test_no_key_returns_401(client):
    r = client.noauth_get("/apps")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"


def test_wrong_key_returns_403(client):
    r = client.bad_key_get("/apps")
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden"


def test_valid_key_returns_200(client):
    r = client.get("/apps")
    assert r.status_code == 200
    assert "apps" in r.json()
