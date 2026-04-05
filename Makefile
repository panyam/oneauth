
test: lint
	go test -v ./...

# Run ALL tests: unit tests → e2e (in-process) → secrets scan -> Keycloak
test-hard: tall e2e secrets testkcl

# Go in-process e2e tests (auth + resource servers via httptest.NewServer)
e2e:
	go test -buildvcs=false -race -count=1 -v ./tests/e2e/

alltests: test
	make downdb updb testpg downdb


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
tall:
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

# Run govulncheck on all modules
vulncheck:
	govulncheck ./...
	@for mod in $(LIBS); do \
		echo "Checking $$mod..."; \
		(cd $$mod && govulncheck ./...) || exit 1; \
	done

# Run gosec (security patterns) — suppress false positives
seccheck:
	gosec -quiet -severity=medium ./...

# Run staticcheck (code quality + deprecated API usage)
lint:
	GOFLAGS=-buildvcs=false staticcheck ./...

# Scan for accidentally committed secrets
secrets:
	gitleaks detect --source . --config .gitleaks.toml -v

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

.PHONY: test test-hard e2e audit updb downdb dblogs testpg upds downds dslogs testds testrealDS upkcl downkcl kcllogs testkcl deploygae gaelogs integ docs setup-tools setup-hooks setup ball tall tidy deps norep rep tag pushtag vulncheck seccheck lint secrets
