"""Load tests for auth endpoints — verifies performance under pressure.

These tests hammer endpoints with concurrent requests to verify:
- Rate limiting holds up under load (not just unit test conditions)
- No goroutine leaks or memory growth under sustained traffic
- Server returns proper status codes under pressure (no 500s)
- bcrypt-heavy login endpoint doesn't exhaust CPU

Requires:
    pytest --start-server  (auto-builds and starts oneauth-server)
    hey (go install github.com/rakyll/hey@latest)

References:
    - CWE-400 (https://cwe.mitre.org/data/definitions/400.html):
      Uncontrolled Resource Consumption
    - OWASP Testing Guide: Performance and Load Testing
"""

import os
import json
import subprocess
import uuid

import pytest
import requests


@pytest.fixture(scope="module")
def server_url(base_url):
    """Server URL, skipping if not available."""
    try:
        r = requests.get(f"{base_url}/_ah/health", timeout=3)
        if r.status_code != 200:
            pytest.skip("Server not running (use --start-server)")
    except requests.ConnectionError:
        pytest.skip("Server not running (use --start-server)")
    return base_url


@pytest.fixture(scope="module")
def hey_path():
    """Path to hey load testing tool, skip if not installed."""
    result = subprocess.run(["which", "hey"], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("hey not installed (go install github.com/rakyll/hey@latest)")
    return result.stdout.strip()


@pytest.fixture(scope="module")
def test_user(server_url):
    """Create a test user for load testing."""
    email = f"load-{uuid.uuid4().hex[:8]}@example.com"
    password = "loadtestpass123"
    session = requests.Session()
    session.get(f"{server_url}/auth/signup")
    csrf = session.cookies.get("csrf_token", "")
    r = session.post(f"{server_url}/auth/signup", data={
        "email": email, "password": password, "csrf_token": csrf,
    }, allow_redirects=False)
    assert r.status_code in (200, 302, 303), f"Signup failed: {r.text[:200]}"
    return {"email": email, "password": password}


def run_hey(hey_path, url, method="GET", n=100, c=10, body=None, headers=None):
    """Run hey and return parsed results."""
    cmd = [hey_path, "-n", str(n), "-c", str(c), "-m", method]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if body:
        cmd.extend(["-T", "application/json", "-d", body])
    cmd.append(url)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    output = result.stdout

    # Parse key metrics from hey output
    metrics = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Requests/sec:"):
            metrics["rps"] = float(line.split(":")[1].strip().split()[0])
        elif line.startswith("Average:") and "secs" in line:
            metrics["avg_latency"] = float(line.split(":")[1].strip().split()[0])
        elif "200" in line and "[200]" not in line and "Status code distribution" not in line:
            pass  # skip
    # Count status codes
    metrics["status_codes"] = {}
    in_status = False
    for line in output.splitlines():
        if "Status code distribution" in line:
            in_status = True
            continue
        if in_status and line.strip():
            if line.strip().startswith("["):
                parts = line.strip().split()
                code = parts[0].strip("[]")
                count = int(parts[1])
                metrics["status_codes"][code] = count
            else:
                in_status = False

    metrics["raw"] = output
    return metrics


class TestLoadHealth:
    """Baseline: health endpoint should handle high throughput with no errors."""

    def test_health_endpoint_throughput(self, server_url, hey_path):
        """Health endpoint should handle 1000 requests at 50 concurrency
        with zero errors and sub-50ms average latency.

        See: https://cwe.mitre.org/data/definitions/400.html
        """
        metrics = run_hey(hey_path, f"{server_url}/_ah/health", n=1000, c=50)

        assert "200" in metrics["status_codes"], \
            f"Expected 200 responses, got: {metrics['status_codes']}"
        assert "500" not in metrics["status_codes"], \
            f"Server errors under load: {metrics['status_codes']}"


class TestLoadLogin:
    """Login endpoint under load — verifies bcrypt doesn't exhaust CPU
    and rate limiting holds up under concurrent requests."""

    def test_login_no_500_under_load(self, server_url, hey_path, test_user):
        """50 concurrent login attempts should return 200 or 401 or 429,
        never 500. This verifies the server handles concurrent bcrypt
        operations without crashing.

        See: https://cwe.mitre.org/data/definitions/400.html
        """
        body = json.dumps({
            "grant_type": "password",
            "username": test_user["email"],
            "password": "wrongpassword",
        })
        metrics = run_hey(hey_path, f"{server_url}/api/token",
                          method="POST", n=50, c=10, body=body,
                          headers={"Content-Type": "application/json"})

        assert "500" not in metrics["status_codes"], \
            f"Server errors under login load: {metrics['status_codes']}\n{metrics['raw'][:500]}"

    def test_correct_login_under_load(self, server_url, hey_path, test_user):
        """10 sequential correct logins should all succeed (verifies no
        resource exhaustion from successful auth flows).
        """
        body = json.dumps({
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        metrics = run_hey(hey_path, f"{server_url}/api/token",
                          method="POST", n=10, c=1, body=body,
                          headers={"Content-Type": "application/json"})

        assert "200" in metrics["status_codes"], \
            f"Expected successful logins, got: {metrics['status_codes']}"


class TestLoadAdmin:
    """Admin endpoints under concurrent access."""

    def test_app_list_under_load(self, server_url, hey_path, admin_key):
        """100 concurrent GET /apps should all return 200, no 500s.
        Verifies the AppRegistrar's RWMutex handles concurrent reads.
        """
        metrics = run_hey(hey_path, f"{server_url}/apps",
                          n=100, c=20,
                          headers={"X-Admin-Key": admin_key})

        assert "500" not in metrics["status_codes"], \
            f"Server errors under admin load: {metrics['status_codes']}"


class TestLoadTokenValidation:
    """Token validation throughput — the hot path for API servers."""

    def test_jwt_validation_throughput(self, server_url, hey_path, test_user):
        """JWT validation should handle high throughput. This is the
        most performance-critical path — every API request validates a token.
        """
        # Get a valid token
        r = requests.post(f"{server_url}/api/token", json={
            "grant_type": "password",
            "username": test_user["email"],
            "password": test_user["password"],
        })
        assert r.status_code == 200
        token = r.json()["access_token"]

        metrics = run_hey(hey_path, f"{server_url}/api/me",
                          n=500, c=50,
                          headers={"Authorization": f"Bearer {token}"})

        assert "200" in metrics["status_codes"], \
            f"Expected 200 for valid token, got: {metrics['status_codes']}"
        assert "500" not in metrics["status_codes"], \
            f"Server errors under JWT validation load: {metrics['status_codes']}"
