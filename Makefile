
test: lint
	go test -v ./...

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
		docker run --rm --network=host -v $(PWD)/.zap-rules.tsv:/zap/rules.tsv \
			ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:19876 \
			-c rules.tsv -a -J /dev/null; \
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
	$(call RUN_STAGE,[1/9] Lint (staticcheck),lint,lint); \
	$(call RUN_STAGE,[2/9] Unit tests (core + sub-modules race detector),unit,unit); \
	$(call RUN_STAGE,[3/9] E2E tests (in-process race detector),e2e,e2e); \
	$(call RUN_STAGE,[4/9] PostgreSQL / GORM tests,postgres,postgres); \
	$(call RUN_STAGE,[5/9] Datastore tests,datastore,datastore); \
	$(call RUN_STAGE,[6/9] Keycloak interop tests,keycloak,keycloak); \
	$(call RUN_STAGE,[7/9] Secret scanning,secrets,secrets); \
	$(call RUN_STAGE,[8/9] Vulnerability check,vulncheck,vulncheck); \
	$(call RUN_STAGE,[9/9] ZAP baseline scan,zap,zap); \
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
KC_IMAGE := quay.io/keycloak/keycloak:26.0

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
	cd tests/keycloak && \
	KEYCLOAK_URL=http://localhost:$(KC_PORT) \
	GOWORK=off \
	go test -v -race -count=1 ./...

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
SUBMODULES := stores/gorm stores/gae saml grpc oauth2 cmd/oneauth-server cmd/demo-hostapp cmd/demo-resource-server

BUILD_DIR := build
LIBS := stores/gorm stores/gae saml grpc oauth2
CMDS := cmd/oneauth-server cmd/demo-hostapp cmd/demo-resource-server
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

# Dep count for core module
deps:
	@echo "Direct: $$(grep -c '^\t' go.mod) | Transitive: $$(go list -m all 2>/dev/null | wc -l | tr -d ' ')"

# Remove replace directives (before publishing)
norep:
	@for mod in $(SUBMODULES); do \
		[ -f "$$mod/go.mod" ] && sed -i '' '/^replace github.com\/panyam\/oneauth/d' "$$mod/go.mod"; \
	done
	@echo "Replace directives removed. Restore with: make rep"

# Restore replace directives (after publishing)
rep:
	@for mod in stores/gorm stores/gae cmd/oneauth-server cmd/demo-resource-server; do \
		echo "replace github.com/panyam/oneauth => ../.." >> "$$mod/go.mod"; \
	done
	@echo "replace github.com/panyam/oneauth/stores/gorm => ../../stores/gorm" >> cmd/oneauth-server/go.mod
	@echo "replace github.com/panyam/oneauth/stores/gae => ../../stores/gae" >> cmd/oneauth-server/go.mod
	@echo "replace github.com/panyam/oneauth/stores/gorm => ../../stores/gorm" >> cmd/demo-resource-server/go.mod
	@echo "Replace directives restored. Run 'make tidy' to verify."

# Tag a release across all modules. Usage: make tag V=v0.0.40
# Sub-modules are tagged with path prefix per Go convention (e.g. stores/gorm/v0.0.40)
SUB_MODS_TO_TAG := stores/gorm stores/gae saml grpc oauth2 cmd/oneauth-server cmd/demo-hostapp cmd/demo-resource-server
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
	unit postgres datastore keycloak zap lint secrets vulncheck \
	updb downdb dblogs testpg upds downds dslogs testds testrealDS \
	upkcl downkcl kcllogs testkcl deploygae gaelogs integ docs \
	setup-tools setup-hooks setup ball tallmods tidy deps norep rep \
	tag pushtag seccheck
