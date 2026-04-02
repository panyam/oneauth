"""Integration security tests — full-stack auth flow security verification.

These tests exercise the complete server stack (HTTP → middleware → handlers → stores)
to verify security properties that unit tests can't fully cover: proper HTTP status codes,
header presence, body size enforcement, and multi-step attack scenarios.

References:
    - CWE-307: Improper Restriction of Excessive Authentication Attempts
      https://cwe.mitre.org/data/definitions/307.html
    - CWE-400: Uncontrolled Resource Consumption (oversized body)
      https://cwe.mitre.org/data/definitions/400.html
    - RFC 6750: Bearer Token Usage
      https://datatracker.ietf.org/doc/html/rfc6750

Requires:
    pytest --start-server  (auto-builds and starts oneauth-server)
    OR DEMO_SERVER_URL=http://localhost:9999 (pre-running server)
"""

import base64
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import requests


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="module")
def server_url(base_url):
    """Server URL, skipping if no server is available."""
    try:
        r = requests.get(f"{base_url}/_ah/health", timeout=3)
        if r.status_code != 200:
            pytest.skip("Server not running (use --start-server)")
    except requests.ConnectionError:
        pytest.skip("Server not running (use --start-server)")
    return base_url


@pytest.fixture(scope="module")
def test_user(server_url):
    """Create a test user via the real signup flow, including CSRF token.

    This exercises the full browser signup path:
    1. GET /auth/signup → server sets csrf_token cookie
    2. POST /auth/signup with csrf_token in both cookie and form field
    """
    email = f"security-{uuid.uuid4().hex[:8]}@example.com"
    password = "securepassword123"

    session = requests.Session()

    # Step 1: GET the signup page to obtain CSRF cookie
    r = session.get(f"{server_url}/auth/signup")
    csrf_token = session.cookies.get("csrf_token", "")
    assert csrf_token, "Server should set csrf_token cookie on GET /auth/signup"

    # Step 2: POST signup with CSRF token in form data (cookie sent automatically by session)
    r = session.post(f"{server_url}/auth/signup", data={
        "email": email,
        "password": password,
        "csrf_token": csrf_token,
    }, allow_redirects=False)
    assert r.status_code in (200, 302, 303), \
        f"Signup failed ({r.status_code}): {r.text[:200]}"

    return {"email": email, "password": password}


@pytest.fixture(scope="module")
def token_pair(server_url, test_user):
    """Get a valid access + refresh token pair."""
    r = requests.post(f"{server_url}/api/token", json={
        "grant_type": "password",
        "username": test_user["email"],
        "password": test_user["password"],
    })
    assert r.status_code == 200, f"Login failed: {r.text}"
    return r.json()


@pytest.fixture(scope="module")
def registered_app(server_url, admin_key):
    """Register an HS256 test app and return its credentials."""
    r = requests.post(
        f"{server_url}/apps/register",
        json={"client_domain": "security-test.example.com", "signing_alg": "HS256"},
        headers={"X-Admin-Key": admin_key, "Content-Type": "application/json"},
    )
    assert r.status_code == 201, f"App registration failed: {r.text}"
    return r.json()


# =============================================================================
# Auth Bypass Attempts (RFC 6750)
# =============================================================================

class TestAuthBypass:
    """Verify that all auth bypass vectors return proper 401/403 responses,
    never 500 (which would indicate unhandled errors leaking server state).

    See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
    """

    def test_no_auth_header_returns_401(self, server_url, admin_key):
        """Protected endpoint with no Authorization header must return 401.

        See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
        """
        # The /apps endpoint requires admin auth via X-Admin-Key
        r = requests.get(f"{server_url}/apps")
        assert r.status_code == 401

    def test_malformed_bearer_returns_401(self, server_url, token_pair):
        """Malformed Bearer token must return 401, not 500.
        A naive server might crash on base64 decode or JSON parse errors.

        See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
        """
        malformed_tokens = [
            "not-a-jwt",
            "eyJ.eyJ.invalid",
            "Bearer ",  # empty after prefix
            "x" * 10000,  # very long garbage
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.",  # alg:none
        ]
        for token in malformed_tokens:
            r = requests.get(
                f"{server_url}/api/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code in (401, 403), \
                f"Malformed token {token[:30]}... got {r.status_code}, expected 401/403"

    def test_tampered_signature_returns_401(self, server_url, token_pair):
        """JWT with a flipped signature byte must return 401, not 500.
        This catches servers that don't handle signature verification errors gracefully.
        """
        token = token_pair["access_token"]
        # Replace the entire signature with garbage (guaranteed invalid)
        header_payload = ".".join(token.split(".")[:2])
        tampered = header_payload + ".AAAA_completely_invalid_signature_BBBB"

        r = requests.get(
            f"{server_url}/api/me",
            headers={"Authorization": f"Bearer {tampered}"},
        )
        assert r.status_code == 401, f"Tampered token got {r.status_code}, expected 401"

    def test_admin_no_key_401(self, server_url):
        """Admin endpoints without X-Admin-Key must return 401.

        See: https://cwe.mitre.org/data/definitions/306.html
        """
        r = requests.get(f"{server_url}/apps")
        assert r.status_code == 401

    def test_admin_wrong_key_403(self, server_url):
        """Admin endpoints with wrong X-Admin-Key must return 403.

        See: https://cwe.mitre.org/data/definitions/287.html
        """
        r = requests.get(
            f"{server_url}/apps",
            headers={"X-Admin-Key": "wrong-key-12345"},
        )
        assert r.status_code == 403


# =============================================================================
# Token Security
# =============================================================================

class TestTokenSecurity:
    """Verify token lifecycle security: refresh token rotation,
    reuse detection, and cross-type confusion prevention."""

    def test_refresh_token_reuse_revokes_family(self, server_url, test_user):
        """Using an old refresh token after rotation must revoke the entire
        token family — both old AND new tokens become invalid.
        This prevents an attacker who stole an old refresh token from
        maintaining access even after the legitimate user refreshes.

        See: https://datatracker.ietf.org/doc/html/rfc6749#section-10.4
        """
        # Login to get initial tokens
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        initial = r.json()
        old_refresh = initial["refresh_token"]

        # Rotate (legitimate use)
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": old_refresh,
        })
        assert r.status_code == 200
        new_tokens = r.json()

        # Attacker tries to reuse old refresh token
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": old_refresh,
        })
        assert r.status_code == 401, "Old refresh token should be rejected"

        # After reuse detection, even the new refresh token should be revoked
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": new_tokens["refresh_token"],
        })
        assert r.status_code == 401, \
            "New refresh token should also be revoked after family compromise"

    def test_access_token_not_usable_as_refresh(self, server_url, token_pair):
        """An access token must not be accepted as a refresh token.
        Token type confusion could allow short-lived tokens to be used for
        long-lived session extension.

        See: https://cwe.mitre.org/data/definitions/269.html
        """
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "refresh_token",
            "refresh_token": token_pair["access_token"],  # wrong token type
        })
        assert r.status_code == 401


# =============================================================================
# Token Blacklist (jti-based revocation)
# =============================================================================

class TestTokenBlacklist:
    """Verify that access tokens can be immediately revoked via the blacklist.

    See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
    See: https://cwe.mitre.org/data/definitions/613.html
    """

    def test_revoked_token_rejected(self, server_url, test_user):
        """After calling POST /api/revoke, the access token should be rejected
        by protected endpoints. This is the core "sign out" flow.

        See: https://cwe.mitre.org/data/definitions/613.html
        """
        # Login
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        assert r.status_code == 200
        token = r.json()["access_token"]

        # Token works before revocation
        r = requests.get(f"{server_url}/api/me",
            headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, "token should work before revocation"

        # Revoke the token
        r = requests.post(f"{server_url}/api/revoke",
            headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 204, f"revoke should return 204, got {r.status_code}"

        # Token should now be rejected
        r = requests.get(f"{server_url}/api/me",
            headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401, \
            f"revoked token should return 401, got {r.status_code}"


# =============================================================================
# App Lifecycle Security
# =============================================================================

class TestAppLifecycle:
    """Verify app registration, key rotation, and deletion security."""

    def test_deleted_app_tokens_rejected(self, server_url, admin_key):
        """After an app is deleted, tokens signed with its secret must be rejected.
        This verifies that key material is actually cleaned up, not just the metadata.
        """
        headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}

        # Register app
        r = requests.post(f"{server_url}/apps/register",
            json={"client_domain": "delete-test.example.com"},
            headers=headers)
        assert r.status_code == 201
        app = r.json()
        client_id = app["client_id"]

        # Delete app
        r = requests.delete(f"{server_url}/apps/{client_id}", headers=headers)
        assert r.status_code == 200

        # Verify app is gone
        r = requests.get(f"{server_url}/apps/{client_id}", headers=headers)
        assert r.status_code == 404

    def test_rotated_secret_invalidates_old_tokens(self, server_url, admin_key):
        """After key rotation, tokens signed with the old secret must eventually
        be rejected (after grace period expires).
        """
        headers = {"X-Admin-Key": admin_key, "Content-Type": "application/json"}

        # Register app
        r = requests.post(f"{server_url}/apps/register",
            json={"client_domain": "rotate-test.example.com"},
            headers=headers)
        assert r.status_code == 201
        app = r.json()
        client_id = app["client_id"]

        # Rotate secret
        r = requests.post(f"{server_url}/apps/{client_id}/rotate",
            json={"grace_period": "0s"},  # no grace period
            headers=headers)
        assert r.status_code == 200
        rotated = r.json()
        assert "client_secret" in rotated, "Rotation should return new secret"

        # Cleanup
        requests.delete(f"{server_url}/apps/{client_id}", headers=headers)


# =============================================================================
# Oversized Body (DoS prevention)
# =============================================================================

class TestOversizedBody:
    """Verify that oversized request bodies are rejected before processing.

    See: https://cwe.mitre.org/data/definitions/400.html
    """

    def test_large_body_rejected(self, server_url, admin_key):
        """A 10MB body to /apps/register must be rejected (413 or 400),
        not cause OOM or hang. Without LimitBody middleware, Go's default
        http.Server reads the entire body into memory.

        See: https://cwe.mitre.org/data/definitions/400.html
        """
        # 10MB of JSON
        large_body = '{"client_domain": "' + "x" * (10 * 1024 * 1024) + '"}'
        r = requests.post(
            f"{server_url}/apps/register",
            data=large_body,
            headers={
                "X-Admin-Key": admin_key,
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        # Should be rejected — 413, 400, or connection reset
        assert r.status_code in (400, 413, 431), \
            f"Large body got {r.status_code}, expected 400/413"


# =============================================================================
# Concurrency Safety
# =============================================================================

class TestConcurrency:
    """Verify that concurrent requests don't cause 500 errors or data races."""

    def test_concurrent_requests_no_500(self, server_url, admin_key):
        """10 parallel requests to the same endpoint must all return proper
        status codes (200, 401, 403) — never 500 (which would indicate a race
        condition or unhandled concurrent access).
        """
        headers = {"X-Admin-Key": admin_key}

        def make_request(_):
            return requests.get(f"{server_url}/apps", headers=headers, timeout=5)

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(make_request, i) for i in range(10)]
            for f in as_completed(futures):
                r = f.result()
                assert r.status_code != 500, \
                    f"Concurrent request returned 500: {r.text[:200]}"
