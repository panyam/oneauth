"""Full host lifecycle — register, get, list, rotate, delete."""

import pytest


@pytest.fixture
def registered_host(client):
    """Register a host and clean it up after the test."""
    r = client.register_host(
        client_domain="lifecycle-test.example.com",
        signing_alg="HS256",
        max_rooms=10,
        max_msg_rate=100.0,
    )
    assert r.status_code == 201
    data = r.json()
    yield data
    # Cleanup — ignore errors if already deleted
    client.delete_host(data["client_id"])


class TestRegister:
    def test_register_returns_credentials(self, client):
        r = client.register_host(
            client_domain="reg-test.example.com",
            signing_alg="HS256",
        )
        assert r.status_code == 201
        data = r.json()
        assert data["client_id"].startswith("host_")
        assert len(data["client_secret"]) == 64  # 32-byte hex
        assert data["signing_alg"] == "HS256"
        assert data["client_domain"] == "reg-test.example.com"
        # Cleanup
        client.delete_host(data["client_id"])

    def test_register_defaults_to_hs256(self, client):
        r = client.register_host(client_domain="default-alg.example.com")
        assert r.status_code == 201
        assert r.json()["signing_alg"] == "HS256"
        client.delete_host(r.json()["client_id"])

    def test_register_wrong_method(self, client):
        r = client.put("/hosts/register")
        assert r.status_code == 405


class TestGetHost:
    def test_get_returns_host(self, client, registered_host):
        r = client.get(f"/hosts/{registered_host['client_id']}")
        assert r.status_code == 200
        assert r.json()["client_id"] == registered_host["client_id"]
        assert r.json()["client_domain"] == "lifecycle-test.example.com"

    def test_get_nonexistent_returns_404(self, client):
        r = client.get("/hosts/host_doesnotexist")
        assert r.status_code == 404


class TestListHosts:
    def test_list_includes_registered(self, client, registered_host):
        r = client.get("/hosts")
        assert r.status_code == 200
        hosts = r.json()["hosts"]
        ids = [h["client_id"] for h in hosts]
        assert registered_host["client_id"] in ids


class TestRotateSecret:
    def test_rotate_returns_new_secret(self, client, registered_host):
        old_secret = registered_host["client_secret"]
        r = client.post(f"/hosts/{registered_host['client_id']}/rotate")
        assert r.status_code == 200
        new_secret = r.json()["client_secret"]
        assert new_secret != old_secret
        assert len(new_secret) == 64

    def test_rotate_nonexistent_returns_404(self, client):
        r = client.post("/hosts/host_doesnotexist/rotate")
        assert r.status_code == 404

    def test_rotate_wrong_method(self, client, registered_host):
        r = client.get(f"/hosts/{registered_host['client_id']}/rotate")
        assert r.status_code == 405


class TestDeleteHost:
    def test_delete_returns_success(self, client):
        # Register then delete (don't use fixture — we manage lifecycle)
        reg = client.register_host(client_domain="delete-test.example.com")
        cid = reg.json()["client_id"]
        r = client.delete(f"/hosts/{cid}")
        assert r.status_code == 200
        assert r.json()["deleted"] is True

        # Verify gone
        r = client.get(f"/hosts/{cid}")
        assert r.status_code == 404

    def test_delete_nonexistent_returns_404(self, client):
        r = client.delete("/hosts/host_doesnotexist")
        assert r.status_code == 404
