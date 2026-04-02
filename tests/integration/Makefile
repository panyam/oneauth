
# Integration tests for oneauth-server
#
# Usage:
#   make all                          # Run all tests against GAE
#   make all BASE_URL=http://localhost:8080 ADMIN_KEY=mykey  # Against local server
#   make autotest                     # Auto-start server, run all tests, stop server
#   make test-security                # Run security tests only (with auto-start)
#   make test-health                  # Run a single test
#   make install                      # Install dependencies

BASE_URL ?=
ADMIN_KEY ?=
GAE_PROJECT ?= oneauthsvc

# Export for pytest/conftest.py
export BASE_URL
export ADMIN_KEY
export GAE_PROJECT

VENV = .venv
PYTEST = $(VENV)/bin/python -m pytest -v

$(VENV): requirements.txt
	uv venv $(VENV)
	uv pip install -r requirements.txt --python $(VENV)/bin/python
	@touch $(VENV)

install: $(VENV)

# Run against an already-running server (GAE or local)
all: $(VENV)
	$(PYTEST) .

# Auto-start a server, run all tests, stop server
autotest: $(VENV)
	$(PYTEST) --start-server .

test-health: $(VENV)
	$(PYTEST) test_01_health.py

test-auth: $(VENV)
	$(PYTEST) test_02_auth_enforcement.py

test-lifecycle: $(VENV)
	$(PYTEST) test_03_host_lifecycle.py

test-jwt: $(VENV)
	$(PYTEST) test_04_jwt_minting.py

test-security: $(VENV)
	$(PYTEST) --start-server test_09_security.py

test-load: $(VENV)
	$(PYTEST) --start-server test_10_load.py

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache

.PHONY: install all autotest test-health test-auth test-lifecycle test-jwt test-security test-load clean
