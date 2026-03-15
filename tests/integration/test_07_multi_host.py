"""Multi-app validation — two apps register, each mints tokens, same resource server validates both."""

import base64
import hashlib
import hmac
import json
import os
import time

import pytest
import requests


@pytest.fixture(scope="module")
def demo_urls():
    return {
        "server": os.environ.get("DEMO_SERVER_URL", "http://localhost:9999"),
        "resource_a": os.environ.get("DEMO_RESOURCE_A_URL", "http://localhost:4001"),
        "resource_b": os.environ.get("DEMO_RESOURCE_B_URL", "http://localhost:4002"),
    }


@pytest.fixture(scope="module")
def admin_key():
    return os.environ.get("DEMO_ADMIN_KEY", "demo-admin-key-12345")


@pytest.fixture(scope="module")
def skip_if_not_running(demo_urls):
    for url in demo_urls.values():
        try:
            r = requests.get(f"{url}/health", timeout=3)
            if r.status_code != 200:
                pytest.skip(f"Service not responding at {url}")
        except requests.ConnectionError:
            pytest.skip(f"Service not running at {url}")


def _mint(client_id, secret_hex_or_str, user_id):
    """Mint a HS256 JWT."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    now = int(time.time())
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": user_id,
            "client_id": client_id,
            "type": "access",
            "scopes": ["collab"],
            "iat": now,
            "exp": now + 900,
        }).encode()
    ).rstrip(b"=")
    sig_input = header + b"." + payload

    # Try hex first, fall back to raw string
    try:
        key = bytes.fromhex(secret_hex_or_str)
    except ValueError:
        key = secret_hex_or_str.encode()

    sig = base64.urlsafe_b64encode(
        hmac.new(key, sig_input, hashlib.sha256).digest()
    ).rstrip(b"=")
    return (sig_input + b"." + sig).decode()


class TestMultiApp:
    def test_two_apps_same_resource_server(self, demo_urls, admin_key, skip_if_not_running):
        server = demo_urls["server"]
        resource = demo_urls["resource_a"]
        headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}

        # Register two apps
        r1 = requests.post(f"{server}/apps/register", json={
            "client_domain": "app-alpha.example.com",
        }, headers=headers)
        assert r1.status_code == 201
        app1 = r1.json()

        r2 = requests.post(f"{server}/apps/register", json={
            "client_domain": "app-beta.example.com",
        }, headers=headers)
        assert r2.status_code == 201
        app2 = r2.json()

        try:
            # Each app mints a token
            token1 = _mint(app1["client_id"], app1["client_secret"], "alice@alpha.com")
            token2 = _mint(app2["client_id"], app2["client_secret"], "bob@beta.com")

            # Both should validate on the same resource server
            v1 = requests.post(f"{resource}/validate", headers={"Authorization": f"Bearer {token1}"})
            assert v1.status_code == 200
            assert v1.json()["valid"] is True
            assert v1.json()["user_id"] == "alice@alpha.com"

            v2 = requests.post(f"{resource}/validate", headers={"Authorization": f"Bearer {token2}"})
            assert v2.status_code == 200
            assert v2.json()["valid"] is True
            assert v2.json()["user_id"] == "bob@beta.com"

        finally:
            requests.delete(f"{server}/apps/{app1['client_id']}", headers=headers)
            requests.delete(f"{server}/apps/{app2['client_id']}", headers=headers)

    def test_cross_resource_server_validation(self, demo_urls, admin_key, skip_if_not_running):
        """Token minted for one app validates on both resource servers."""
        server = demo_urls["server"]
        headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}

        r = requests.post(f"{server}/apps/register", json={
            "client_domain": "cross-resource.example.com",
        }, headers=headers)
        assert r.status_code == 201
        app = r.json()

        try:
            token = _mint(app["client_id"], app["client_secret"], "cross@test.com")

            # Validate on resource server A
            va = requests.post(f"{demo_urls['resource_a']}/validate",
                             headers={"Authorization": f"Bearer {token}"})
            assert va.status_code == 200
            assert va.json()["resource_server"] == "resource-a"

            # Validate on resource server B
            vb = requests.post(f"{demo_urls['resource_b']}/validate",
                             headers={"Authorization": f"Bearer {token}"})
            assert vb.status_code == 200
            assert vb.json()["resource_server"] == "resource-b"

        finally:
            requests.delete(f"{server}/apps/{app['client_id']}", headers=headers)

    def test_swapped_secret_rejected(self, demo_urls, admin_key, skip_if_not_running):
        """Token signed with app-A's secret but claiming app-B's client_id is rejected."""
        server = demo_urls["server"]
        resource = demo_urls["resource_a"]
        headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}

        r1 = requests.post(f"{server}/apps/register", json={
            "client_domain": "swap-a.example.com",
        }, headers=headers)
        app_a = r1.json()

        r2 = requests.post(f"{server}/apps/register", json={
            "client_domain": "swap-b.example.com",
        }, headers=headers)
        app_b = r2.json()

        try:
            # Mint with app-B's client_id but app-A's secret
            token = _mint(app_b["client_id"], app_a["client_secret"], "sneaky@evil.com")

            v = requests.post(f"{resource}/validate", headers={"Authorization": f"Bearer {token}"})
            assert v.status_code == 401  # Signature mismatch

        finally:
            requests.delete(f"{server}/apps/{app_a['client_id']}", headers=headers)
            requests.delete(f"{server}/apps/{app_b['client_id']}", headers=headers)
