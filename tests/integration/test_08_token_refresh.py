"""Token refresh flow — login, get token pair, refresh, verify new token works."""

import os
import uuid

import pytest
import requests


@pytest.fixture(scope="module")
def server_url(base_url):
    return base_url


@pytest.fixture(scope="module")
def skip_if_not_running(server_url):
    try:
        r = requests.get(f"{server_url}/_ah/health", timeout=3)
        if r.status_code != 200:
            pytest.skip("OneAuth server not running")
    except requests.ConnectionError:
        pytest.skip("OneAuth server not running")


@pytest.fixture
def test_user(server_url, skip_if_not_running):
    """Create a test user via signup with CSRF token and return credentials."""
    email = f"refresh-{uuid.uuid4().hex[:8]}@example.com"
    password = "testpass1234"

    session = requests.Session()
    session.get(f"{server_url}/auth/signup")
    csrf_token = session.cookies.get("csrf_token", "")

    r = session.post(f"{server_url}/auth/signup", data={
        "email": email, "password": password, "csrf_token": csrf_token,
    }, allow_redirects=False)
    assert r.status_code in (200, 302, 303), f"Signup failed: {r.text}"

    return {"email": email, "password": password}


class TestTokenRefresh:
    def test_password_grant_returns_token_pair(self, server_url, test_user, skip_if_not_running):
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        assert r.status_code == 200, f"Login failed: {r.text}"
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] > 0

    def test_refresh_grant_returns_new_tokens(self, server_url, test_user, skip_if_not_running):
        # Get initial token pair
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        assert r.status_code == 200
        initial = r.json()

        # Use refresh token to get new pair
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": initial["refresh_token"],
        })
        assert r.status_code == 200, f"Refresh failed: {r.text}"
        refreshed = r.json()

        # New tokens should be different
        assert refreshed["access_token"] != initial["access_token"]
        assert refreshed["refresh_token"] != initial["refresh_token"]

    def test_old_refresh_token_rejected_after_rotation(self, server_url, test_user, skip_if_not_running):
        # Get initial token pair
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        initial = r.json()
        old_refresh = initial["refresh_token"]

        # Rotate (use refresh token once)
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": old_refresh,
        })
        assert r.status_code == 200

        # Try to reuse old refresh token (should fail — token reuse detection)
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": old_refresh,
        })
        assert r.status_code == 401

    def test_logout_revokes_refresh_token(self, server_url, test_user, skip_if_not_running):
        # Login
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        tokens = r.json()

        # Logout
        r = requests.post(f"{server_url}/api/logout", json={
            "refresh_token": tokens["refresh_token"],
        })
        assert r.status_code == 204

        # Refresh token should now be invalid
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
        })
        assert r.status_code == 401
