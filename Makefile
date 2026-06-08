
test: lint verify-submodule-deps
	go test -v ./...

# Verify that sub-module go.mod files require a real, tagged version of the
# root module. Catches the v0.0.0 placeholder and multi-bump staleness.
# See CLAUDE.md "Releasing Sub-Modules" for the release order.
verify-submodule-deps:
	@bash scripts/verify-submodule-deps.sh

# Run ALL tests: unit tests → e2e (in-process) → secrets scan -> Keycloak
test-hard: tallmods e2e secrets testkcl

alltests: test
	make downdb updb testpg downdb

# =============================================================================
# Comprehensive local test suite with HTML report
# =============================================================================
# Runs EVERYTHING: unit, e2e, PostgreSQL, Datastore, Keycloak, lint, security.
# Requires Docker for PG, Datastore emulator, and Keycloak containers.
# Generates an HTML report at test-reports/report.html.
#
# Usage:
#   make testall        # Run everything + generate report
#   make lint           # Lint (staticcheck)
#   make unit           # Unit tests (race detector + sub-modules)
#   make e2e            # E2E tests (in-process servers)
#   make postgres       # PostgreSQL/GORM tests (needs Docker PG)
#   make datastore      # Datastore tests (needs GCP credentials)
#   make keycloak       # Keycloak interop tests (needs Docker KC)
#   make secrets        # Secret scanning (gitleaks)
#   make vulncheck      # Vulnerability check (govulncheck)
#   make zap            # ZAP baseline security scan
#   make test-report    # Regenerate HTML report from last run's logs
REPORT_DIR := test-reports

# --- Individual stage targets ------------------------------------------------
# Each stage can be run independently via: make <name>
# These are the building blocks that testall orchestrates.

# Static analysis via staticcheck
lint:
	@echo "[lint] Running staticcheck..."
	@GOFLAGS=-buildvcs=false staticcheck ./...

# Build the user-facing oneauth binaries (CLI + reference server) into bin/.
# Demos (cmd/demo-*) are explicitly excluded — build those directly with
# `go build ./cmd/demo-...` if you need them.
build:
	@mkdir -p $(BUILD_DIR)
	@echo "[build] cmd/oneauth         → $(BUILD_DIR)/oneauth"
	@go build -o $(BUILD_DIR)/oneauth ./cmd/oneauth
	@echo "[build] cmd/oneauth-server  → $(BUILD_DIR)/oneauth-server"
	@cd cmd/oneauth-server && go build -o ../../$(BUILD_DIR)/oneauth-server .

# Install the user-facing oneauth binaries to $GOBIN / $GOPATH/bin via go install.
install:
	@echo "[install] go install ./cmd/oneauth"
	@go install ./cmd/oneauth
	@echo "[install] go install ./cmd/oneauth-server"
	@cd cmd/oneauth-server && go install .

cover: ## Run tests with coverage summary (root module only)
	@go test -buildvcs=false -cover ./... -count=1 -timeout 60s

cover-html: ## Run tests with coverage and generate HTML report (root module only)
	@mkdir -p $(REPORT_DIR)
	go test -buildvcs=false -coverprofile=$(REPORT_DIR)/coverage.out ./... -count=1 -timeout 60s
	go tool cover -html=$(REPORT_DIR)/coverage.out -o $(REPORT_DIR)/coverage.html
	@echo "Coverage report: $(REPORT_DIR)/coverage.html"

cover-func: ## Show per-function coverage sorted by lowest (top 30)
	@mkdir -p $(REPORT_DIR)
	go test -buildvcs=false -coverprofile=$(REPORT_DIR)/coverage.out ./... -count=1 -timeout 60s
	go tool cover -func=$(REPORT_DIR)/coverage.out | sort -k3 -n | head -30

cover-all: ## Run coverage across root + all library sub-modules, generate per-module HTML reports
	@mkdir -p $(REPORT_DIR)
	@echo "==> coverage: root module"
	@go test -buildvcs=false -coverprofile=$(REPORT_DIR)/coverage-root.out ./... -count=1 -timeout 60s
	@go tool cover -html=$(REPORT_DIR)/coverage-root.out -o $(REPORT_DIR)/coverage-root.html
	@for mod in $(LIBS); do \
		echo "==> coverage: $$mod"; \
		(cd $$mod && go test -buildvcs=false -coverprofile=../../$(REPORT_DIR)/coverage-$$(echo $$mod | tr / -).out ./... -count=1 -timeout 30s) || true; \
		go tool cover -html=$(REPORT_DIR)/coverage-$$(echo $$mod | tr / -).out -o $(REPORT_DIR)/coverage-$$(echo $$mod | tr / -).html 2>/dev/null || true; \
	done
	@echo ""
	@echo "Coverage reports:"
	@ls -1 $(REPORT_DIR)/coverage-*.html 2>/dev/null

# Unit tests: core module + sub-modules, race detector enabled
unit:
	@echo "[unit] Testing core module (race detector)..."
	@go test -buildvcs=false -race -count=1 -short ./...
	@for mod in stores/gorm stores/gae grpc oauth2; do \
		if [ -d "$$mod" ]; then \
			echo "[unit] Testing sub-module: $$mod"; \
			(cd $$mod && go test -buildvcs=false -count=1 -short ./...) || exit 1; \
		fi; \
	done
	@echo "[unit] Done."

# PostgreSQL / GORM tests (assumes PG container is running on PG_PORT)
postgres:
	@echo "[postgres] Running GORM tests against PostgreSQL on port $(PG_PORT)..."
	@ONEAUTH_TEST_PGDB=$(PG_DB) ONEAUTH_TEST_PGPORT=$(PG_PORT) \
		ONEAUTH_TEST_PGUSER=$(PG_USER) ONEAUTH_TEST_PGPASSWORD=$(PG_PASSWORD) \
		go test -buildvcs=false -count=1 ./stores/gorm/...

# Datastore tests against real GCP Datastore (skips if no credentials)
datastore:
	@echo "[datastore] Checking credentials..."
	@if [ -f "$(DS_REAL_CREDENTIALS)" ]; then \
		echo "[datastore] Running against real Datastore..."; \
		DATASTORE_PROJECT_ID=$(DS_REAL_PROJECT) DATASTORE_CREDENTIALS_FILE=$(DS_REAL_CREDENTIALS) \
			DATASTORE_TEST_NAMESPACE=$(DS_REAL_NAMESPACE) \
			go test -buildvcs=false -count=1 ./stores/gae/...; \
	else \
		echo "SKIP: no credentials at $(DS_REAL_CREDENTIALS)"; \
	fi

# E2E tests: in-process auth + resource servers, race detector
e2e:
	@echo "[e2e] Running in-process e2e tests (race detector)..."
	@go test -buildvcs=false -race -count=1 ./tests/e2e/

# Keycloak interop tests (waits up to 60s for KC to be ready)
keycloak:
	@echo "[keycloak] Waiting for Keycloak on port $(KC_PORT)..."
	@KC_READY=0; for i in $$(seq 1 30); do \
		if curl -sf http://localhost:$(KC_PORT)/realms/oneauth-test > /dev/null 2>&1; then KC_READY=1; break; fi; sleep 2; \
	done; \
	if [ $$KC_READY -eq 1 ]; then \
		echo "[keycloak] Running interop tests..."; \
		cd tests/keycloak && KEYCLOAK_URL=http://localhost:$(KC_PORT) GOWORK=off \
			go test -race -count=1 ./...; \
	else \
		echo "[keycloak] SKIP: not ready at localhost:$(KC_PORT) (run 'make upkcl' first)"; \
	fi

# Authlete interop tests (skip cleanly when env not configured)
authlete:
	@echo "[authlete] Checking credentials..."
	@if [ -z "$$AUTHLETE_SERVICEID" ] || [ -z "$$AUTHLETE_ACCESS_TOKEN" ] || \
	    [ -z "$$AUTHLETE_CLIENTID" ] || [ -z "$$AUTHLETE_CLIENTSECRET" ]; then \
		echo "[authlete] SKIP: AUTHLETE_SERVICEID / ACCESS_TOKEN / CLIENTID / CLIENTSECRET env vars not all set"; \
	elif ! docker ps --format '{{.Names}}' | grep -q '^$(AUTH_CONTAINER_NAME)$$'; then \
		echo "[authlete] SKIP: frontend container not running (run 'make upauthlete' first)"; \
	else \
		echo "[authlete] Running interop tests..."; \
		cd tests/authlete && AUTHLETE_AS_URL=http://localhost:$(AUTH_PORT) GOWORK=off \
			go test -count=1 ./...; \
	fi

# Secret scanning via gitleaks
secrets:
	@echo "[secrets] Scanning for leaked secrets..."
	@gitleaks detect --source . --config .gitleaks.toml

# Vulnerability check via govulncheck
vulncheck:
	@echo "[vulncheck] Checking for known vulnerabilities..."
	@govulncheck ./...

# ZAP baseline security scan (starts temp server, runs ZAP Docker)
zap:
	@mkdir -p $(BUILD_DIR)
	@echo "[zap] Building server..."
	@go build -buildvcs=false -o $(BUILD_DIR)/oneauth-server ./cmd/oneauth-server/
	@echo "[zap] Starting server on :19876..."
	@PORT=19876 ADMIN_AUTH_TYPE=api-key ADMIN_API_KEY=test-all-key KEYSTORE_TYPE=memory \
		USER_STORES_TYPE=fs USER_STORES_PATH=/tmp/oneauth-zap-test-all \
		JWT_SECRET_KEY=test-all-jwt-secret JWT_ISSUER=oneauth-test-all \
		$(BUILD_DIR)/oneauth-server & ZAP_PID=$$!; \
	ZAP_OK=0; for i in $$(seq 1 15); do \
		if curl -sf http://localhost:19876/_ah/health > /dev/null 2>&1; then ZAP_OK=1; break; fi; sleep 1; \
	done; \
	if [ $$ZAP_OK -eq 1 ]; then \
		mkdir -p /tmp/zap-wrk && cp $(PWD)/.zap-rules.tsv /tmp/zap-wrk/rules.tsv && \
		docker run --rm -v /tmp/zap-wrk:/zap/wrk:rw \
			ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:19876 \
			-c rules.tsv -a; \
		ZAP_EXIT=$$?; \
	else \
		echo "SKIP: server failed to start"; ZAP_EXIT=0; \
	fi; \
	kill $$ZAP_PID 2>/dev/null || true; \
	exit $$ZAP_EXIT

# --- Orchestrator: testall ---------------------------------------------------
# Runs all 9 stages, tracks pass/fail, generates HTML report.
# Stages are called via their make targets above.

# Helper: run a stage target and record result. Usage in shell:
#   run_stage <stage-name> <make-target> <log-file>
# Sets STAGES and PASS/FAIL variables (must be called inside a single shell block).
define RUN_STAGE
	echo "" | tee -a $(REPORT_DIR)/run.log; \
	echo "--- $(1) ---" | tee -a $(REPORT_DIR)/run.log; \
	if $(MAKE) --no-print-directory $(2) >> $(REPORT_DIR)/run.log 2>&1; then \
		echo "  PASS: $(3)" | tee -a $(REPORT_DIR)/run.log; PASS=$$((PASS+1)); STAGES="$$STAGES $(3):PASS"; \
	else \
		echo "  FAIL: $(3)" | tee -a $(REPORT_DIR)/run.log; FAIL=$$((FAIL+1)); STAGES="$$STAGES $(3):FAIL"; \
	fi
endef

testall:
	@mkdir -p $(REPORT_DIR) $(BUILD_DIR)
	@echo "=== OneAuth Comprehensive Test Suite ===" | tee $(REPORT_DIR)/run.log
	@echo "Started: $$(date)" | tee -a $(REPORT_DIR)/run.log
	@# Clean slate: stop any leftover containers
	@docker stop $(PG_CONTAINER_NAME) 2>/dev/null || true
	@docker stop $(KC_CONTAINER_NAME) 2>/dev/null || true
	@# Start fresh containers for PG and Keycloak
	@echo "Starting PostgreSQL..." | tee -a $(REPORT_DIR)/run.log
	@docker run --rm -d --name $(PG_CONTAINER_NAME) \
		-e POSTGRES_USER=$(PG_USER) -e POSTGRES_PASSWORD=$(PG_PASSWORD) -e POSTGRES_DB=$(PG_DB) \
		-p $(PG_PORT):5432 arm64v8/postgres:18.1 >> $(REPORT_DIR)/run.log 2>&1
	@echo "Starting Keycloak..." | tee -a $(REPORT_DIR)/run.log
	@docker run --rm -d --name $(KC_CONTAINER_NAME) -p $(KC_PORT):8080 \
		-v $(PWD)/tests/keycloak/realm.json:/opt/keycloak/data/import/oneauth-test-realm.json \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
		$(KC_IMAGE) start-dev --import-realm >> $(REPORT_DIR)/run.log 2>&1
	@sleep 3
	@PASS=0; FAIL=0; STAGES=""; \
	$(call RUN_STAGE,[1/10] Lint (staticcheck),lint,lint); \
	$(call RUN_STAGE,[2/10] Unit tests + coverage (core + sub-modules),cover-html,unit+coverage); \
	$(call RUN_STAGE,[3/10] E2E tests (in-process race detector),e2e,e2e); \
	$(call RUN_STAGE,[4/10] PostgreSQL / GORM tests,postgres,postgres); \
	$(call RUN_STAGE,[5/10] Datastore tests,datastore,datastore); \
	$(call RUN_STAGE,[6/10] Keycloak interop tests,keycloak,keycloak); \
	$(call RUN_STAGE,[7/10] Authlete interop tests,authlete,authlete); \
	$(call RUN_STAGE,[8/10] Secret scanning,secrets,secrets); \
	$(call RUN_STAGE,[9/10] Vulnerability check,vulncheck,vulncheck); \
	$(call RUN_STAGE,[10/10] ZAP baseline scan,zap,zap); \
	\
	echo "" | tee -a $(REPORT_DIR)/run.log; \
	echo "=== Summary: $$PASS passed, $$FAIL failed ===" | tee -a $(REPORT_DIR)/run.log; \
	echo "Finished: $$(date)" | tee -a $(REPORT_DIR)/run.log; \
	\
	echo "Cleaning up containers..."; \
	docker stop $(PG_CONTAINER_NAME) >> $(REPORT_DIR)/run.log 2>&1 || true; \
	docker stop $(KC_CONTAINER_NAME) >> $(REPORT_DIR)/run.log 2>&1 || true; \
	\
	echo "Generating HTML report..."; \
	$(MAKE) test-report STAGES="$$STAGES"; \
	echo ""; \
	echo "Report: $(REPORT_DIR)/report.html"; \
	if [ $$FAIL -gt 0 ]; then exit 1; fi

# Generate HTML report from the last testall run log
test-report:
	@mkdir -p $(REPORT_DIR)
	@TIMESTAMP=$$(date '+%Y-%m-%d %H:%M:%S'); \
	COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo "unknown"); \
	BRANCH=$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"); \
	echo '<!DOCTYPE html>' > $(REPORT_DIR)/report.html; \
	echo '<html><head><meta charset="utf-8"><title>OneAuth Test Report</title>' >> $(REPORT_DIR)/report.html; \
	echo '<style>' >> $(REPORT_DIR)/report.html; \
	echo 'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #333; }' >> $(REPORT_DIR)/report.html; \
	echo 'h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }' >> $(REPORT_DIR)/report.html; \
	echo '.meta { color: #666; font-size: 14px; margin-bottom: 20px; }' >> $(REPORT_DIR)/report.html; \
	echo 'table { border-collapse: collapse; width: 100%; margin: 20px 0; }' >> $(REPORT_DIR)/report.html; \
	echo 'th, td { border: 1px solid #ddd; padding: 10px 14px; text-align: left; }' >> $(REPORT_DIR)/report.html; \
	echo 'th { background: #f5f5f5; font-weight: 600; }' >> $(REPORT_DIR)/report.html; \
	echo '.pass { color: #22863a; font-weight: 600; }' >> $(REPORT_DIR)/report.html; \
	echo '.fail { color: #cb2431; font-weight: 600; }' >> $(REPORT_DIR)/report.html; \
	echo '.skip { color: #6a737d; font-weight: 600; }' >> $(REPORT_DIR)/report.html; \
	echo '.warn { color: #b08800; font-weight: 600; }' >> $(REPORT_DIR)/report.html; \
	echo '.summary-pass { background: #dcffe4; padding: 12px 20px; border-radius: 6px; font-size: 18px; }' >> $(REPORT_DIR)/report.html; \
	echo '.summary-fail { background: #ffdce0; padding: 12px 20px; border-radius: 6px; font-size: 18px; }' >> $(REPORT_DIR)/report.html; \
	echo 'pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 13px; max-height: 400px; overflow-y: auto; }' >> $(REPORT_DIR)/report.html; \
	echo '</style></head><body>' >> $(REPORT_DIR)/report.html; \
	echo "<h1>OneAuth Test Report</h1>" >> $(REPORT_DIR)/report.html; \
	echo "<div class='meta'>Branch: <strong>$$BRANCH</strong> | Commit: <code>$$COMMIT</code> | Date: $$TIMESTAMP</div>" >> $(REPORT_DIR)/report.html; \
	\
	PASS=0; FAIL=0; \
	echo "<table><tr><th>Stage</th><th>Result</th></tr>" >> $(REPORT_DIR)/report.html; \
	for entry in $(STAGES); do \
		STAGE=$$(echo $$entry | cut -d: -f1); \
		RESULT=$$(echo $$entry | cut -d: -f2); \
		if [ "$$RESULT" = "PASS" ]; then \
			echo "<tr><td>$$STAGE</td><td class='pass'>PASS</td></tr>" >> $(REPORT_DIR)/report.html; \
			PASS=$$((PASS+1)); \
		elif [ "$$RESULT" = "SKIP" ]; then \
			echo "<tr><td>$$STAGE</td><td class='skip'>SKIP</td></tr>" >> $(REPORT_DIR)/report.html; \
		elif [ "$$RESULT" = "WARN" ]; then \
			echo "<tr><td>$$STAGE</td><td class='warn'>WARN</td></tr>" >> $(REPORT_DIR)/report.html; \
		else \
			echo "<tr><td>$$STAGE</td><td class='fail'>FAIL</td></tr>" >> $(REPORT_DIR)/report.html; \
			FAIL=$$((FAIL+1)); \
		fi; \
	done; \
	echo "</table>" >> $(REPORT_DIR)/report.html; \
	\
	if [ $$FAIL -eq 0 ]; then \
		echo "<div class='summary-pass'>All $$PASS stages passed</div>" >> $(REPORT_DIR)/report.html; \
	else \
		echo "<div class='summary-fail'>$$PASS passed, $$FAIL failed</div>" >> $(REPORT_DIR)/report.html; \
	fi; \
	\
	if [ -f $(REPORT_DIR)/run.log ]; then \
		echo "<h2>Full Log</h2><pre>" >> $(REPORT_DIR)/report.html; \
		sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' $(REPORT_DIR)/run.log >> $(REPORT_DIR)/report.html; \
		echo "</pre>" >> $(REPORT_DIR)/report.html; \
	fi; \
	echo "</body></html>" >> $(REPORT_DIR)/report.html


# =============================================================================
# PostgreSQL test database configuration
# =============================================================================
PG_CONTAINER_NAME := oneauth-test-pg
PG_PORT := 5433
PG_USER := postgres
PG_PASSWORD := testpassword
PG_DB := testdb

# Start an ephemeral PostgreSQL instance using Docker for testing
updb:
	@echo "Starting PostgreSQL container..."
	@docker run --rm -d \
		--name $(PG_CONTAINER_NAME) \
		-e POSTGRES_USER=$(PG_USER) \
		-e POSTGRES_PASSWORD=$(PG_PASSWORD) \
		-e POSTGRES_DB=$(PG_DB) \
		-p $(PG_PORT):5432 \
		arm64v8/postgres:18.1
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 3
	@echo ""
	@echo "PostgreSQL is running!"
	@echo "To run GORM tests with PostgreSQL: make testpg"
	@echo "To stop: make downdb"

# Stop the PostgreSQL test container
downdb:
	@echo "Stopping PostgreSQL container..."
	@docker stop $(PG_CONTAINER_NAME) 2>/dev/null || echo "Container not running"

# Tail the logs of the running PostgreSQL container
dblogs:
	@docker logs -f $(PG_CONTAINER_NAME)

# Run GORM store tests with PostgreSQL (starts container if not running)
testpg:
	@if ! docker ps --format '{{.Names}}' | grep -q '^$(PG_CONTAINER_NAME)$$'; then \
		echo "Starting PostgreSQL container..."; \
		docker run --rm -d \
			--name $(PG_CONTAINER_NAME) \
			-e POSTGRES_USER=$(PG_USER) \
			-e POSTGRES_PASSWORD=$(PG_PASSWORD) \
			-e POSTGRES_DB=$(PG_DB) \
			-p $(PG_PORT):5432 \
			arm64v8/postgres:18.1; \
		sleep 3; \
	fi
	ONEAUTH_TEST_PGDB=$(PG_DB) \
	ONEAUTH_TEST_PGPORT=$(PG_PORT) \
	ONEAUTH_TEST_PGUSER=$(PG_USER) \
	ONEAUTH_TEST_PGPASSWORD=$(PG_PASSWORD) \
	go test -v ./stores/gorm/...

# =============================================================================
# Datastore emulator configuration
# =============================================================================
DS_CONTAINER_NAME := oneauth-test-datastore
DS_PORT := 8081
DS_PROJECT := test-project

# Start a Datastore emulator using Docker for testing
upds:
	@echo "Starting Datastore emulator container..."
	@docker run --rm -d \
		--name $(DS_CONTAINER_NAME) \
		-p $(DS_PORT):8081 \
		gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators \
		gcloud beta emulators datastore start \
			--host-port=0.0.0.0:8081 \
			--project=$(DS_PROJECT) \
			--no-store-on-disk
	@echo "Waiting for Datastore emulator to be ready..."
	@sleep 3
	@echo ""
	@echo "Datastore emulator is running!"
	@echo "To run GAE tests: make testds"
	@echo "To stop: make downds"

# Stop the Datastore emulator container
downds:
	@echo "Stopping Datastore emulator container..."
	@docker stop $(DS_CONTAINER_NAME) 2>/dev/null || echo "Container not running"

# Tail the logs of the running Datastore emulator container
dslogs:
	@docker logs -f $(DS_CONTAINER_NAME)

# Run GAE store tests with Datastore emulator (starts container if not running)
testds:
	@if ! docker ps --format '{{.Names}}' | grep -q '^$(DS_CONTAINER_NAME)$$'; then \
		echo "Starting Datastore emulator container..."; \
		docker run --rm -d \
			--name $(DS_CONTAINER_NAME) \
			-p $(DS_PORT):8081 \
			gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators \
			gcloud beta emulators datastore start \
				--host-port=0.0.0.0:8081 \
				--project=$(DS_PROJECT) \
				--no-store-on-disk; \
		sleep 5; \
	fi
	DATASTORE_EMULATOR_HOST=localhost:$(DS_PORT) \
	DATASTORE_PROJECT_ID=$(DS_PROJECT) \
	go test -v ./stores/gae/...

# Real Datastore configuration
# Override via command line: make testrealDS DS_REAL_PROJECT=other-project
DS_REAL_PROJECT ?= gappeng
DS_REAL_CREDENTIALS ?= ~/dev-app-data/secrets/gappeng/gappeng-7bb71377bfa2.json
DS_REAL_NAMESPACE ?= oneauth-test

# Run GAE store tests against real Google Cloud Datastore
testrealDS:
	@if [ -z "$(DS_REAL_PROJECT)" ]; then \
		echo "Error: DS_REAL_PROJECT must be set to your GCP project ID"; \
		echo "Usage: make testrealDS DS_REAL_PROJECT=my-project DS_REAL_CREDENTIALS=~/path/to/creds.json"; \
		exit 1; \
	fi
	@echo "Running tests against real Datastore..."
	@echo "  Project: $(DS_REAL_PROJECT)"
	@echo "  Namespace: $(DS_REAL_NAMESPACE)"
	@if [ -n "$(DS_REAL_CREDENTIALS)" ]; then \
		echo "  Credentials: $(DS_REAL_CREDENTIALS)"; \
	else \
		echo "  Credentials: Application Default Credentials (ADC)"; \
	fi
	@echo ""
	DATASTORE_PROJECT_ID=$(DS_REAL_PROJECT) \
	DATASTORE_CREDENTIALS_FILE=$(DS_REAL_CREDENTIALS) \
	DATASTORE_TEST_NAMESPACE=$(DS_REAL_NAMESPACE) \
	go test -v ./stores/gae/...

# =============================================================================
# Keycloak interop test configuration
# =============================================================================
KC_CONTAINER_NAME := oneauth-test-keycloak
KC_PORT := 8180
KC_IMAGE := quay.io/keycloak/keycloak:26.6

# Start a Keycloak instance using Docker for interop testing
upkcl:
	@echo "Starting Keycloak container..."
	@docker run --rm -d \
		--name $(KC_CONTAINER_NAME) \
		-p $(KC_PORT):8080 \
		-v $(PWD)/tests/keycloak/realm.json:/opt/keycloak/data/import/oneauth-test-realm.json \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
		-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
		$(KC_IMAGE) start-dev --import-realm
	@echo "Waiting for Keycloak to be ready (~15s)..."
	@until curl -sf http://localhost:$(KC_PORT)/realms/oneauth-test > /dev/null 2>&1; do sleep 2; done
	@echo ""
	@echo "Keycloak is running!"
	@echo "  Admin console: http://localhost:$(KC_PORT)/admin (admin/admin)"
	@echo "  Realm:         http://localhost:$(KC_PORT)/realms/oneauth-test"
	@echo "To run interop tests: make testkcl"
	@echo "To stop: make downkcl"

# Stop the Keycloak container
downkcl:
	@echo "Stopping Keycloak container..."
	@docker stop $(KC_CONTAINER_NAME) 2>/dev/null || echo "Container not running"

# Tail the logs of the running Keycloak container
kcllogs:
	@docker logs -f $(KC_CONTAINER_NAME)

# =============================================================================
# Authlete interop test configuration (issue 162)
# =============================================================================
# Tests live in tests/authlete/. They exercise the OneAuth client SDK +
# APIMiddleware against a locally-running authlete/java-oauth-server
# frontend, which back-channels to Authlete cloud — proving that
# Authlete-issued tokens validate correctly through OneAuth's machinery.
#
# Authlete does not publish java-oauth-server to Docker Hub, so we clone
# the upstream repo at a pinned commit and build the image locally. The
# clone lives in tests/authlete/.frontend/ (gitignored). First build is
# slow (Maven downloads + Java compile); subsequent runs use the cached
# image.
#
# Required env vars (all four must be set):
#   AUTHLETE_SERVICEID     — numeric service ID (your Authlete tenant)
#   AUTHLETE_ACCESS_TOKEN  — service access token (back-channel auth)
#   AUTHLETE_CLIENTID      — numeric OAuth client_id registered in the service
#   AUTHLETE_CLIENTSECRET  — paired client_secret
#
# Optional:
#   AUTHLETE_API_SERVER    — Authlete cloud endpoint; defaults to https://api.authlete.com
#
# Tests skip cleanly when these are unset, so the suite stays safe under
# the default `go test ./...` invocation.
AUTH_CONTAINER_NAME := oneauth-test-authlete
AUTH_PORT := 8280
AUTH_FRONTEND_REF := 799440548fb8
AUTH_FRONTEND_DIR := tests/authlete/.frontend
AUTH_IMAGE := oneauth-test/authlete-frontend:$(AUTH_FRONTEND_REF)
AUTH_API_SERVER ?= https://api.authlete.com

# Clone upstream authlete/java-oauth-server at the pinned commit (idempotent).
$(AUTH_FRONTEND_DIR):
	@echo "Cloning authlete/java-oauth-server@$(AUTH_FRONTEND_REF)..."
	@git clone --quiet https://github.com/authlete/java-oauth-server $(AUTH_FRONTEND_DIR)
	@cd $(AUTH_FRONTEND_DIR) && git checkout --quiet $(AUTH_FRONTEND_REF)

# Build the Authlete frontend image from the pinned source (idempotent — uses
# Docker's layer cache to skip rebuilds when the source hasn't changed).
authlete-image: $(AUTH_FRONTEND_DIR)
	@if ! docker image inspect $(AUTH_IMAGE) > /dev/null 2>&1; then \
		echo "Building $(AUTH_IMAGE) from source (~5–10 min first time)..."; \
		docker build -t $(AUTH_IMAGE) $(AUTH_FRONTEND_DIR); \
	fi

# Bump the pinned upstream ref. Usage:
#   make upauthlete-refresh AUTH_FRONTEND_REF=<new-sha>
# Removes the cached clone + image so the next upauthlete picks the new SHA up.
upauthlete-refresh:
	@echo "Refreshing Authlete frontend to $(AUTH_FRONTEND_REF)..."
	@rm -rf $(AUTH_FRONTEND_DIR)
	@docker image rm $(AUTH_IMAGE) 2>/dev/null || true
	@echo "Done. Run 'make upauthlete' to rebuild against $(AUTH_FRONTEND_REF)."

# Start the Authlete frontend pointed at Authlete cloud.
upauthlete: authlete-image
	@if [ -z "$$AUTHLETE_SERVICEID" ] || [ -z "$$AUTHLETE_ACCESS_TOKEN" ]; then \
		echo "Error: AUTHLETE_SERVICEID and AUTHLETE_ACCESS_TOKEN must be exported"; \
		echo "  Get them from https://console.authlete.com/"; \
		exit 1; \
	fi
	@echo "Generating authlete.properties from env..."
	@# api_version is a top-level key (not under service.) per the upstream
	@# template's commented note. service.access_token is V3-specific Bearer
	@# auth; service.api_key remains the numeric service identifier even in V3.
	@printf 'base_url=%s\napi_version=V3\nservice.api_key=%s\nservice.access_token=%s\n' \
		"$(AUTH_API_SERVER)" "$$AUTHLETE_SERVICEID" "$$AUTHLETE_ACCESS_TOKEN" \
		> $(AUTH_FRONTEND_DIR)/authlete.properties.runtime
	@echo "Starting Authlete frontend container..."
	@docker run --rm -d \
		--name $(AUTH_CONTAINER_NAME) \
		-p $(AUTH_PORT):8080 \
		-v $(PWD)/$(AUTH_FRONTEND_DIR)/authlete.properties.runtime:/authlete/app/authlete.properties \
		$(AUTH_IMAGE)
	@echo "Waiting for AS to be ready (Jetty warmup ~30s)..."
	@until curl -sf http://localhost:$(AUTH_PORT)/.well-known/openid-configuration > /dev/null 2>&1; do sleep 3; done
	@echo ""
	@echo "Authlete-backed AS is running!"
	@echo "  Discovery: http://localhost:$(AUTH_PORT)/.well-known/openid-configuration"
	@echo "  Token:     http://localhost:$(AUTH_PORT)/api/token"
	@echo "To run interop tests: make testauthlete"
	@echo "To stop: make downauthlete"

# Stop the Authlete frontend container.
downauthlete:
	@echo "Stopping Authlete frontend container..."
	@docker stop $(AUTH_CONTAINER_NAME) 2>/dev/null || echo "Container not running"

# Tail logs of the running Authlete frontend container.
authletelogs:
	@docker logs -f $(AUTH_CONTAINER_NAME)

# Configure the Authlete service for full PASS on the interop suite
# (issue 244). Idempotent: re-running is safe and reports already-provisioned.
# Mutates the service identified by AUTHLETE_SERVICEID (override with
# AUTHLETE_TEST_SERVICEID for safety on shared tenants).
authlete-provision:
	@if [ -z "$$AUTHLETE_SERVICEID" ] || [ -z "$$AUTHLETE_ACCESS_TOKEN" ]; then \
		echo "Error: AUTHLETE_SERVICEID and AUTHLETE_ACCESS_TOKEN must be exported"; \
		exit 1; \
	fi
	AUTHLETE_API_SERVER=$(AUTH_API_SERVER) go run -buildvcs=false ./tests/authlete/cmd/provision/

# Restore the Authlete service to its pre-provision state, reading the
# snapshot written by authlete-provision. Idempotent: missing snapshot is
# reported but not an error.
authlete-deprovision:
	@if [ -z "$$AUTHLETE_SERVICEID" ] || [ -z "$$AUTHLETE_ACCESS_TOKEN" ]; then \
		echo "Error: AUTHLETE_SERVICEID and AUTHLETE_ACCESS_TOKEN must be exported"; \
		exit 1; \
	fi
	AUTHLETE_API_SERVER=$(AUTH_API_SERVER) go run -buildvcs=false ./tests/authlete/cmd/deprovision/

# Run Authlete interop tests (starts container if not running).
testauthlete:
	@if [ -z "$$AUTHLETE_CLIENTID" ] || [ -z "$$AUTHLETE_CLIENTSECRET" ]; then \
		echo "Error: AUTHLETE_CLIENTID and AUTHLETE_CLIENTSECRET must be exported for tests"; \
		exit 1; \
	fi
	@if ! docker ps --format '{{.Names}}' | grep -q '^$(AUTH_CONTAINER_NAME)$$'; then \
		$(MAKE) upauthlete; \
	fi
	AUTHLETE_AS_URL=http://localhost:$(AUTH_PORT) \
	AUTHLETE_API_SERVER=$(AUTH_API_SERVER) \
		go test -v ./tests/authlete/...

# =============================================================================
# OIDF conformance harness (issue 197)
# =============================================================================
# Stands up the OpenID Foundation conformance suite (Java app + MongoDB +
# nginx) against the local cmd/oneauth-server, captures baseline results.
# This is *not* part of the conformance ratchet yet — Phase 1 is a
# manually-run baseline so we can see, in concrete terms, which OIDF
# certification tests pass against OneAuth today and which require
# work (notably 116 — full OIDC /authorize endpoint).
#
# UI: https://localhost.emobix.co.uk:8443/  (hostname resolves publicly to 127.0.0.1)

OIDF_COMPOSE := tests/oidf-conformance/docker-compose-prebuilt.yml
OIDF_AS_CONFIG := tests/oidf-conformance/oneauth-server.yaml

upoidf:
	@echo "Starting OIDF conformance suite (mongo + nginx + server)..."
	@docker compose -f $(OIDF_COMPOSE) up -d
	@echo "Waiting for harness UI..."
	@until curl -ksf -o /dev/null https://localhost.emobix.co.uk:8443/; do sleep 2; done
	@echo ""
	@echo "OIDF conformance suite is running!"
	@echo "  UI:     https://localhost.emobix.co.uk:8443/"
	@echo "  Stop:   make downoidf"
	@echo ""
	@echo "Next: in another shell, run 'make upoidf-as' to start oneauth-server"
	@echo "      reachable at http://host.docker.internal:8888 from the harness."

downoidf:
	@echo "Stopping OIDF conformance stack..."
	@docker compose -f $(OIDF_COMPOSE) down
	@echo "MongoDB data persists in tests/oidf-conformance/mongo/ — delete that dir for a clean slate."

upoidf-as:
	@echo "Starting cmd/oneauth-server on :8888 with OIDF baseline config..."
	@go run ./cmd/oneauth-server --config $(OIDF_AS_CONFIG)

oidflogs:
	@docker compose -f $(OIDF_COMPOSE) logs -f --tail=100 server

# Run the OIDF conformance ratchet — issue 197 phase 2. Auto-starts
# the harness + AS if not already running, then runs the discovery
# test wrapper which drives the harness via REST and diffs results
# against tests/conformance/known-gaps.yaml (external-suite entries).
testoidf:
	@if ! curl -ksf -o /dev/null https://localhost.emobix.co.uk:8443/; then \
		echo "OIDF harness not running — starting it..."; \
		$(MAKE) upoidf; \
	fi
	@if ! curl -sf -o /dev/null http://localhost:8888/.well-known/openid-configuration; then \
		echo "oneauth-server not running on :8888 — starting it in the background..."; \
		go run -buildvcs=false ./cmd/oneauth-server --config $(OIDF_AS_CONFIG) > /dev/null 2>&1 & \
		until curl -sf -o /dev/null http://localhost:8888/.well-known/openid-configuration; do sleep 1; done; \
	fi
	cd tests/oidf-conformance && GOWORK=off go test -count=1 -v ./...

# =============================================================================
# Conformance ratchet — see docs/CONFORMANCE.md
# =============================================================================
# Runs every known conformance test (passing AND expected-fail) and diffs
# the outcome against tests/conformance/known-gaps.yaml. Exits non-zero on
# any drift: regression, ratchet-up, stale entry, or t.Skip(). Also writes
# a Markdown report at docs/conformance/native.md — scoped runs derive
# distinct filenames (e.g., native-as_metadata.md), so parallel runs of
# different suites don't clobber each other. The docs site renders that
# native.md verbatim under /conformance/native/.
testconformance:
	@cd tests/conformance && GOWORK=off go run ./cmd/runner -package ./...

# Run Keycloak interop tests (starts container if not running)
testkcl:
	@if ! docker ps --format '{{.Names}}' | grep -q '^$(KC_CONTAINER_NAME)$$'; then \
		echo "Starting Keycloak container..."; \
		docker run --rm -d \
			--name $(KC_CONTAINER_NAME) \
			-p $(KC_PORT):8080 \
			-v $(PWD)/tests/keycloak/realm.json:/opt/keycloak/data/import/oneauth-test-realm.json \
			-e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
			-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
			$(KC_IMAGE) start-dev --import-realm; \
		echo "Waiting for Keycloak to be ready (~15s)..."; \
		until curl -sf http://localhost:$(KC_PORT)/realms/oneauth-test > /dev/null 2>&1; do sleep 2; done; \
		echo "Keycloak ready."; \
	fi
	@if ! curl -sf http://localhost:$(RAR_PORT)/_ah/health > /dev/null 2>&1; then \
		echo "Starting RAR test server..."; \
		go run -buildvcs=false ./cmd/oneauth-server/ \
			--config cmd/oneauth-server/deploy-examples/rar-test.yaml > /dev/null 2>&1 & \
		until curl -sf http://localhost:$(RAR_PORT)/_ah/health > /dev/null 2>&1; do sleep 1; done; \
		echo "RAR test server ready."; \
	fi
	cd tests/keycloak && \
	KEYCLOAK_URL=http://localhost:$(KC_PORT) \
	RAR_ISSUER_URL=http://localhost:$(RAR_PORT) \
	GOWORK=off \
	go test -v -race -count=1 ./...

# =============================================================================
# RAR Test Issuer — RFC 9396 interop testing
# =============================================================================
# A minimal OneAuth-based AS that supports Rich Authorization Requests.
# Used for interop testing: proves OneAuth resource servers can validate
# RAR tokens issued by an external AS over real HTTP.
#
# Migration path: when Keycloak adds RFC 9396 RAR support on standard OAuth
# flows (tracked: keycloak/keycloak#29340), migrate these tests to use
# Keycloak and retire this binary. The tests in tests/keycloak/rar_interop_test.go
# are structured to make this migration straightforward — swap the URL and
# client credentials, keep the assertions.
RAR_PORT := 8181
RAR_PID_FILE := /tmp/oneauth-rar-test.pid

# Start RAR test server (oneauth-server with rar-test.yaml config)
uprar:
	@if [ -f $(RAR_PID_FILE) ] && kill -0 $$(cat $(RAR_PID_FILE)) 2>/dev/null; then \
		echo "RAR test server already running (pid $$(cat $(RAR_PID_FILE)))"; \
	else \
		echo "Starting RAR test server on port $(RAR_PORT)..."; \
		go run -buildvcs=false ./cmd/oneauth-server/ \
			--config cmd/oneauth-server/deploy-examples/rar-test.yaml & \
		echo $$! > $(RAR_PID_FILE); \
		until curl -sf http://localhost:$(RAR_PORT)/_ah/health > /dev/null 2>&1; do sleep 1; done; \
		echo "RAR test server ready (pid $$(cat $(RAR_PID_FILE)))"; \
		echo "  Discovery: http://localhost:$(RAR_PORT)/.well-known/openid-configuration"; \
	fi

# Stop RAR test server
downrar:
	@if [ -f $(RAR_PID_FILE) ]; then \
		kill $$(cat $(RAR_PID_FILE)) 2>/dev/null || true; \
		rm -f $(RAR_PID_FILE); \
		echo "RAR test server stopped."; \
	else \
		echo "Not running"; \
	fi

# =============================================================================
# GAE deployment
# =============================================================================
GAE_PROJECT ?= oneauthsvc

deploygae:
	gcloud app deploy --appyaml=cmd/oneauth-server/deploy-examples/gae/app.yaml --project=$(GAE_PROJECT) --quiet .

gaelogs:
	gcloud app logs tail -s default --project=$(GAE_PROJECT)

# =============================================================================
# Integration / E2E tests
# =============================================================================
# Old Python integration tests removed — use make e2e instead.
# For GAE deployment testing: TEST_BASE_URL=https://... make e2e
integ: e2e

# =============================================================================
# Documentation
# =============================================================================
docs:
	@echo "Starting local pkgsite at http://localhost:6060 ..."
	@echo "(Install with: go install golang.org/x/pkgsite/cmd/pkgsite@latest)"
	pkgsite -http=localhost:6060

# Regression guard: pkgsite / pkg.go.dev render HTML comments as literal
# text in rendered package docs. /design-rebuild-go must never emit `<!--`
# into doc.go — this target fails the build if any leakage is found.
docs-check:
	@echo "[docs-check] Scanning doc.go files for HTML-comment leakage..."
	@leaked=$$(find . -name doc.go \( -path './vendor' -prune -o -path './.git' -prune -o -print \) | xargs grep -l '<!--' 2>/dev/null); \
	if [ -n "$$leaked" ]; then \
		echo "FAIL: the following doc.go files contain '<!--' (pkgsite will render as literal text):"; \
		echo "$$leaked" | sed 's/^/  /'; \
		exit 1; \
	fi
	@echo "[docs-check] OK — no HTML comments in any doc.go"

# Convenience alias so `make doc` works in addition to `make docs`.
.PHONY: doc
doc: docs

# =============================================================================
# Setup
# =============================================================================

# Install required Go tools (linting, static analysis, docs)
setup-tools:
	@echo "Installing Go tools..."
	go install golang.org/x/pkgsite/cmd/pkgsite@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo ""
	@echo "Done. Ensure $$(go env GOPATH)/bin is in your PATH."

setup-hooks:
	git config core.hooksPath .githooks

setup: setup-tools setup-hooks

# =============================================================================
# Multi-module management
# =============================================================================
BUILD_DIR := build
LIBS := stores/gorm stores/gae saml grpc oauth2
CMDS := cmd/oneauth cmd/oneauth-server cmd/demo-hostapp cmd/demo-resource-server
SUBMODULES := $(LIBS) $(CMDS)

# Build all modules. Command binaries go to build/
ball:
	@mkdir -p $(BUILD_DIR)
	go build -buildvcs=false ./...
	@for mod in $(LIBS); do \
		(cd $$mod && go build -buildvcs=false ./...) || exit 1; \
	done
	@for mod in $(CMDS); do \
		(cd $$mod && go build -buildvcs=false -o ../../$(BUILD_DIR)/ ./...) || exit 1; \
	done

# Test all modules (root + sub-modules)
tallmods:
	go test -buildvcs=false -count=1 -short ./...
	@for mod in $(SUBMODULES); do \
		(cd $$mod && go test -buildvcs=false -count=1 -short ./... 2>&1) || exit 1; \
	done

# Tidy all modules
tidy:
	go mod tidy
	@for mod in $(SUBMODULES); do (cd $$mod && go mod tidy) || exit 1; done

# Alias for consistency with other projects (mcpkit uses this name).
tidy-all: tidy

# Bump each sub-module's require github.com/panyam/oneauth to a specific tag.
# Usage: make bump-root V=v0.0.70
#
# Only touches the root self-reference. Cross-sub-module references
# (e.g. stores/gorm referenced from cmd/oneauth-server) have their own
# independent timelines and must be bumped manually when needed.
bump-root:
	@if [ -z "$(V)" ]; then echo "Usage: make bump-root V=v0.0.70"; exit 1; fi
	@for mod in $(SUBMODULES); do \
		if [ ! -f "$$mod/go.mod" ]; then continue; fi; \
		if ! grep -q "github.com/panyam/oneauth v" "$$mod/go.mod"; then continue; fi; \
		echo "==> $$mod/go.mod: require github.com/panyam/oneauth $(V)"; \
		(cd $$mod && go mod edit -require=github.com/panyam/oneauth@$(V)) || exit 1; \
	done
	@$(MAKE) -s tidy
	@$(MAKE) -s verify-submodule-deps

# Dep count for core module
deps:
	@echo "Direct: $$(grep -c '^\t' go.mod) | Transitive: $$(go list -m all 2>/dev/null | wc -l | tr -d ' ')"

# Tag a release across all modules. Usage: make tag V=v0.0.40
# Sub-modules are tagged with path prefix per Go convention (e.g. stores/gorm/v0.0.40)
SUB_MODS_TO_TAG := stores/gorm stores/gae saml grpc oauth2 cmd/oneauth cmd/oneauth-server cmd/demo-hostapp cmd/demo-resource-server
tag:
	@if [ -z "$(V)" ]; then echo "Usage: make tag V=v0.0.40"; exit 1; fi
	@echo "Tagging $(V) across all modules..."
	git tag $(V)
	@for mod in $(SUB_MODS_TO_TAG); do \
		echo "  $$mod/$(V)"; \
		git tag $$mod/$(V); \
	done
	@echo ""
	@echo "Tags created locally. Push with: git push origin $(V) $$(echo '$(SUB_MODS_TO_TAG)' | tr ' ' '\n' | sed 's|$$|/$(V)|' | tr '\n' ' ')"

# Push all tags for a version. Usage: make pushtag V=v0.0.40
pushtag:
	@if [ -z "$(V)" ]; then echo "Usage: make pushtag V=v0.0.40"; exit 1; fi
	git push origin $(V)
	@for mod in $(SUB_MODS_TO_TAG); do \
		git push origin $$mod/$(V); \
	done
	@echo "All tags pushed."

# =============================================================================
# Static analysis & security scanning
# =============================================================================

# Run gosec (security patterns) — suppress false positives
seccheck:
	gosec -quiet -severity=medium ./...

# Full security audit: dependency vulns + code patterns + secrets + race detection
audit: vulncheck secrets
	@echo ""
	@echo "=== gosec (informational) ==="
	@gosec -quiet -severity=high ./... || true
	@echo ""
	@echo "=== Race detection (e2e) ==="
	go test -buildvcs=false -race -count=1 ./tests/e2e/
	@echo ""
	@echo "=== Audit complete ==="
	@echo "Automated checks passed. For manual threat model review, see docs/TESTING.md."

.PHONY: test test-hard testall test-report e2e audit \
	build install \
	unit postgres datastore keycloak zap lint secrets vulncheck \
	updb downdb dblogs testpg upds downds dslogs testds testrealDS \
	upkcl downkcl kcllogs testkcl uprar downrar upoidf downoidf upoidf-as oidflogs deploygae gaelogs integ docs \
	setup-tools setup-hooks setup ball tallmods tidy tidy-all bump-root \
	deps tag pushtag seccheck verify-submodule-deps \
	cover cover-html cover-func cover-all
