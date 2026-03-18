
test:
	go test -v ./...

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
# GAE deployment
# =============================================================================
GAE_PROJECT ?= oneauthsvc

deploygae:
	gcloud app deploy --appyaml=cmd/oneauth-server/deploy-examples/gae/app.yaml --project=$(GAE_PROJECT) --quiet .

gaelogs:
	gcloud app logs tail -s default --project=$(GAE_PROJECT)

# =============================================================================
# Integration tests
# =============================================================================
integ:
	$(MAKE) -C tests/integration all

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

.PHONY: test updb downdb dblogs testpg upds downds dslogs testds testrealDS deploygae gaelogs integ docs setup-tools setup-hooks setup
