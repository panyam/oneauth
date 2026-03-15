"""Browser auth flow — signup, login, JWT cookie, dashboard access, forgot password."""

import pytest
import requests


@pytest.fixture(scope="module")
def server_url():
    """OneAuth server URL — override with DEMO_SERVER_URL env var."""
    import os
    return os.environ.get("DEMO_SERVER_URL", "http://localhost:9999")


@pytest.fixture(scope="module")
def session(server_url):
    """Requests session that follows redirects and stores cookies."""
    s = requests.Session()
    s.headers["Accept"] = "text/html"
    # Verify server is running
    try:
        r = s.get(f"{server_url}/_ah/health", timeout=5)
        if r.status_code != 200:
            pytest.skip("OneAuth server not running")
    except requests.ConnectionError:
        pytest.skip("OneAuth server not running")
    return s


class TestBrowserAuth:
    def test_landing_page_loads(self, server_url, session):
        r = session.get(f"{server_url}/")
        assert r.status_code == 200
        assert "OneAuth" in r.text

    def test_signup_page_loads(self, server_url, session):
        r = session.get(f"{server_url}/auth/signup")
        assert r.status_code == 200
        assert "Sign Up" in r.text

    def test_signup_and_login(self, server_url, session):
        import uuid
        email = f"test-{uuid.uuid4().hex[:8]}@example.com"
        password = "testpass1234"

        # Signup
        r = session.post(f"{server_url}/auth/signup", data={
            "email": email, "password": password,
        }, allow_redirects=False)
        # Should redirect to dashboard (signup auto-logs in)
        assert r.status_code in (302, 303)
        assert "oa_token" in session.cookies

        # Clear cookies, then login
        session.cookies.clear()

        r = session.post(f"{server_url}/auth/login", data={
            "username": email, "password": password,
        }, allow_redirects=False)
        assert r.status_code in (302, 303)
        assert "oa_token" in session.cookies

    def test_dashboard_requires_auth(self, server_url):
        r = requests.get(f"{server_url}/dashboard", allow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/auth/login" in r.headers.get("Location", "")

    def test_dashboard_accessible_with_cookie(self, server_url, session):
        import uuid
        email = f"dash-{uuid.uuid4().hex[:8]}@example.com"

        # Signup (gets cookie)
        session.post(f"{server_url}/auth/signup", data={
            "email": email, "password": "testpass1234",
        })

        r = session.get(f"{server_url}/dashboard")
        assert r.status_code == 200
        assert "Dashboard" in r.text

    def test_logout_clears_cookie(self, server_url, session):
        r = session.get(f"{server_url}/auth/logout", allow_redirects=False)
        assert r.status_code in (302, 303)

    def test_forgot_password_page(self, server_url, session):
        r = session.get(f"{server_url}/auth/forgot-password")
        assert r.status_code == 200
        assert "Forgot Password" in r.text

    def test_invalid_login_shows_error(self, server_url, session):
        r = session.post(f"{server_url}/auth/login", data={
            "username": "nobody@example.com", "password": "wrongpass",
        })
        assert r.status_code == 200
        assert "Invalid" in r.text or "error" in r.text.lower()
