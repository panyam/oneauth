"""Shared fixtures for oneauth-server integration tests.

Usage:
    # Against deployed GAE (reads admin key from Secret Manager):
    pytest tests/integration/

    # Against a local server:
    BASE_URL=http://localhost:8080 ADMIN_KEY=mykey pytest tests/integration/

    # Override GAE project:
    GAE_PROJECT=my-project pytest tests/integration/
"""

import os
import subprocess
import pytest
import requests


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
        pytest.skip("ADMIN_KEY not set and gcloud Secret Manager unavailable")


@pytest.fixture(scope="session")
def gae_project():
    return os.environ.get("GAE_PROJECT", "oneauthsvc")


@pytest.fixture(scope="session")
def base_url(gae_project):
    return os.environ.get("BASE_URL", f"https://{gae_project}.uw.r.appspot.com")


@pytest.fixture(scope="session")
def admin_key(gae_project):
    return _get_admin_key(gae_project)


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

    def bad_key_get(self, path: str) -> requests.Response:
        """GET with an incorrect admin key."""
        return requests.get(
            f"{self.base_url}{path}",
            headers={"X-Admin-Key": "wrong-key-value"},
        )

    def register_host(self, **kwargs) -> requests.Response:
        return self.post("/hosts/register", json=kwargs)

    def delete_host(self, client_id: str) -> requests.Response:
        return self.delete(f"/hosts/{client_id}")


@pytest.fixture(scope="session")
def client(base_url, admin_key):
    return OneAuthClient(base_url, admin_key)
