"""Shared fixtures for oneauth-server integration tests.

Usage:
    # Against deployed GAE (reads admin key from Secret Manager):
    pytest tests/integration/

    # Against a local server (already running):
    BASE_URL=http://localhost:8080 ADMIN_KEY=mykey pytest tests/integration/

    # Auto-start a server for testing (builds + runs cmd/oneauth-server):
    pytest tests/integration/ --start-server

    # Override GAE project:
    GAE_PROJECT=my-project pytest tests/integration/
"""

import os
import signal
import subprocess
import sys
import tempfile
import time

import pytest
import requests


# =============================================================================
# pytest CLI options
# =============================================================================

def pytest_addoption(parser):
    parser.addoption(
        "--start-server",
        action="store_true",
        default=False,
        help="Auto-start a oneauth-server for integration testing (builds from source)",
    )


# =============================================================================
# Server management
# =============================================================================

def _get_admin_key(project: str) -> str:
    """Fetch admin key from Secret Manager if not set in env."""
    key = os.environ.get("ADMIN_KEY", "")
    if key:
        return key
    try:
        result = subprocess.run(
            ["gcloud", "secrets", "versions", "access", "latest",
             "--secret=oneauth-admin-key", f"--project={project}"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _wait_for_server(url: str, timeout: int = 15) -> bool:
    """Wait for a server to respond to health checks."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/_ah/health", timeout=2)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    return False


class ManagedServer:
    """Builds, starts, and stops a oneauth-server for testing."""

    def __init__(self):
        self.process = None
        self.tmpdir = None
        self.port = "19876"  # unlikely to conflict
        self.admin_key = "test-admin-key-for-integ"
        self.jwt_secret = "test-jwt-secret-for-integ-12345"

    @property
    def base_url(self):
        return f"http://localhost:{self.port}"

    def start(self):
        # Find project root (two levels up from tests/integration/)
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        server_dir = os.path.join(root, "cmd", "oneauth-server")
        binary = os.path.join(root, "build", "oneauth-server-test")

        # Build the server
        print(f"\n  Building oneauth-server from {server_dir}...")
        result = subprocess.run(
            ["go", "build", "-buildvcs=false", "-o", binary, "."],
            cwd=server_dir,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            pytest.fail(f"Failed to build oneauth-server:\n{result.stderr}")

        # Create temp directory for FS stores
        self.tmpdir = tempfile.mkdtemp(prefix="oneauth-integ-")

        # Start with env-based config (no config file needed)
        env = {
            **os.environ,
            "PORT": self.port,
            "ADMIN_AUTH_TYPE": "api-key",
            "ADMIN_API_KEY": self.admin_key,
            "KEYSTORE_TYPE": "memory",
            "USER_STORES_TYPE": "fs",
            "USER_STORES_PATH": self.tmpdir,
            "JWT_SECRET_KEY": self.jwt_secret,
            "JWT_ISSUER": "oneauth-integ-test",
        }

        print(f"  Starting oneauth-server on port {self.port}...")
        self.process = subprocess.Popen(
            [binary],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if not _wait_for_server(self.base_url):
            self.stop()
            stderr = self.process.stderr.read().decode() if self.process.stderr else ""
            pytest.fail(f"Server failed to start within 15s.\nStderr: {stderr}")

        print(f"  Server running at {self.base_url} (PID {self.process.pid})")

    def stop(self):
        if self.process:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

        if self.tmpdir:
            import shutil
            shutil.rmtree(self.tmpdir, ignore_errors=True)
            self.tmpdir = None


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def gae_project():
    return os.environ.get("GAE_PROJECT", "oneauthsvc")


@pytest.fixture(scope="session")
def managed_server(request):
    """Optionally start a managed server if --start-server is passed."""
    if not request.config.getoption("--start-server"):
        return None
    server = ManagedServer()
    server.start()
    request.addfinalizer(server.stop)
    return server


@pytest.fixture(scope="session")
def base_url(gae_project, managed_server):
    if managed_server:
        return managed_server.base_url
    url = os.environ.get("BASE_URL", "")
    if url:
        return url
    # Fall back to DEMO_SERVER_URL for backward compat
    url = os.environ.get("DEMO_SERVER_URL", "")
    if url:
        return url
    return f"https://{gae_project}.uw.r.appspot.com"


@pytest.fixture(scope="session")
def admin_key(gae_project, managed_server):
    if managed_server:
        return managed_server.admin_key
    key = _get_admin_key(gae_project)
    if not key:
        pytest.skip("ADMIN_KEY not set and gcloud Secret Manager unavailable (use --start-server for auto-start)")
    return key


@pytest.fixture(scope="session")
def jwt_secret(managed_server):
    """JWT secret for the test server (only available with --start-server)."""
    if managed_server:
        return managed_server.jwt_secret
    return os.environ.get("JWT_SECRET_KEY", "")


class OneAuthClient:
    """Thin HTTP client for oneauth-server."""

    def __init__(self, base_url: str, admin_key: str):
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key
        self.session = requests.Session()
        self.session.headers.update({
            "X-Admin-Key": admin_key,
            "Content-Type": "application/json",
        })

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(f"{self.base_url}{path}", **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", **kwargs)

    def delete(self, path: str, **kwargs) -> requests.Response:
        return self.session.delete(f"{self.base_url}{path}", **kwargs)

    def put(self, path: str, **kwargs) -> requests.Response:
        return self.session.put(f"{self.base_url}{path}", **kwargs)

    def noauth_get(self, path: str) -> requests.Response:
        """GET without admin key."""
        return requests.get(f"{self.base_url}{path}")

    def noauth_post(self, path: str, **kwargs) -> requests.Response:
        """POST without admin key."""
        return requests.post(f"{self.base_url}{path}", **kwargs)

    def bad_key_get(self, path: str) -> requests.Response:
        """GET with an incorrect admin key."""
        return requests.get(
            f"{self.base_url}{path}",
            headers={"X-Admin-Key": "wrong-key-value"},
        )

    def register_app(self, **kwargs) -> requests.Response:
        return self.post("/apps/register", json=kwargs)

    def delete_app(self, client_id: str) -> requests.Response:
        return self.delete(f"/apps/{client_id}")


@pytest.fixture(scope="session")
def client(base_url, admin_key):
    return OneAuthClient(base_url, admin_key)
