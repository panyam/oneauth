"""Federated auth flow — register app, mint resource server token, resource server validates, claims correct."""

import base64
import json
import os

import pytest
import requests


# demo_urls and admin_key fixtures come from conftest.py


@pytest.fixture(scope="module")
def skip_if_not_running(demo_urls):
    """Skip tests if demo stack (auth server + resource servers) is not running."""
    for name, url in demo_urls.items():
        if not url or "localhost:0" in url:
            pytest.skip(f"{name} not configured (resource servers not started)")
        health = f"{url}/_ah/health" if name == "server" else f"{url}/health"
        try:
            r = requests.get(health, timeout=3)
            if r.status_code != 200:
                pytest.skip(f"{name} not responding at {url}")
        except requests.ConnectionError:
            pytest.skip(f"{name} not running at {url}")


def _decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    return json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))


def _mint_resource_jwt(client_id, client_secret, user_id="testuser@example.com"):
    """Mint a resource-server-scoped JWT using the oneauth library convention."""
    import hashlib
    import hmac
    import time as _time

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    now = int(_time.time())
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": user_id,
            "client_id": client_id,
            "type": "access",
            "scopes": ["collab"],
            "max_rooms": 10,
            "max_msg_rate": 100,
            "iat": now,
            "exp": now + 900,
        }).encode()
    ).rstrip(b"=")
    sig_input = header + b"." + payload
    sig = base64.urlsafe_b64encode(
        hmac.new(client_secret.encode(), sig_input, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (sig_input + b"." + sig).decode()


class TestFederatedFlow:
    def test_register_app_and_validate_token(self, demo_urls, admin_key, skip_if_not_running):
        server = demo_urls["server"]
        resource = demo_urls["resource_a"]

        # Register an app
        r = requests.post(f"{server}/apps/register", json={
            "client_domain": "fed-test.example.com",
            "signing_alg": "HS256",
        }, headers={
            "X-Admin-Key": admin_key,
            "Content-Type": "application/json",
        })
        assert r.status_code == 201, f"Registration failed: {r.text}"
        app = r.json()
        client_id = app["client_id"]
        client_secret = app["client_secret"]

        try:
            # Mint a resource server token
            token = _mint_resource_jwt(client_id, client_secret, "fed-user@example.com")
            claims = _decode_jwt_payload(token)
            assert claims["sub"] == "fed-user@example.com"
            assert claims["client_id"] == client_id

            # Validate against resource server
            r = requests.post(f"{resource}/validate", headers={
                "Authorization": f"Bearer {token}",
            })
            assert r.status_code == 200, f"Validation failed: {r.text}"
            result = r.json()
            assert result["valid"] is True
            assert result["user_id"] == "fed-user@example.com"
            assert result["custom_claims"]["client_id"] == client_id

        finally:
            # Cleanup
            requests.delete(f"{server}/apps/{client_id}", headers={
                "X-Admin-Key": admin_key,
            })

    def test_wrong_secret_rejected_by_resource_server(self, demo_urls, admin_key, skip_if_not_running):
        server = demo_urls["server"]
        resource = demo_urls["resource_a"]

        # Register app
        r = requests.post(f"{server}/apps/register", json={
            "client_domain": "bad-secret.example.com",
        }, headers={
            "X-Admin-Key": admin_key,
            "Content-Type": "application/json",
        })
        assert r.status_code == 201
        app = r.json()
        client_id = app["client_id"]

        try:
            # Mint with wrong secret
            token = _mint_resource_jwt(client_id, "wrong-secret-value", "hacker@evil.com")

            # Should be rejected by resource server
            r = requests.post(f"{resource}/validate", headers={
                "Authorization": f"Bearer {token}",
            })
            assert r.status_code == 401

        finally:
            requests.delete(f"{server}/apps/{client_id}", headers={
                "X-Admin-Key": admin_key,
            })
