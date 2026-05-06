# Examples top-level Makefile
#
# Batch operations across all examples. Per-example commands
# (demo, demo-plain, demo-ci, serve, walkthrough) live in each
# example's own Makefile.

EXAMPLES := $(sort $(wildcard [0-9][0-9]-*/))

# Regenerate WALKTHROUGH.md for every example that has Go files.
walkthroughs:
	@count=0; for dir in $(EXAMPLES); do \
		if ls $$dir/*.go >/dev/null 2>&1; then \
			echo "[walkthrough] $$dir"; \
			$(MAKE) -C $$dir walkthrough; \
			count=$$((count + 1)); \
		else \
			echo "[skip]        $$dir (no Go files yet)"; \
		fi; \
	done; \
	echo "Done. Generated $$count WALKTHROUGH.md files."

# Smoke test every example in non-interactive mode.
demos-ci:
	@for dir in $(EXAMPLES); do \
		if ls $$dir/*.go >/dev/null 2>&1; then \
			echo "[demo-ci] $$dir"; \
			$(MAKE) -C $$dir demo-ci || exit 1; \
		fi; \
	done

# List all examples.
list:
	@for dir in $(EXAMPLES); do \
		echo "  $$dir"; \
	done

# =============================================================================
# Keycloak for examples (separate from test KC on port 8180)
# =============================================================================
KC_EXAMPLES_PORT := 8280
KC_EXAMPLES_CONTAINER := oneauth-examples-keycloak
KC_EXAMPLES_IMAGE := quay.io/keycloak/keycloak:26.6
KC_EXAMPLES_REALM := $(PWD)/keycloak-realm.json

upkcl:
	@if docker ps --format '{{.Names}}' | grep -q '^$(KC_EXAMPLES_CONTAINER)$$'; then \
		echo "Examples Keycloak already running on port $(KC_EXAMPLES_PORT)"; \
	else \
		echo "Starting Keycloak for examples on port $(KC_EXAMPLES_PORT)..."; \
		docker run --rm -d \
			--name $(KC_EXAMPLES_CONTAINER) \
			-p $(KC_EXAMPLES_PORT):8080 \
			-v $(KC_EXAMPLES_REALM):/opt/keycloak/data/import/oneauth-examples-realm.json \
			-e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
			-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
			$(KC_EXAMPLES_IMAGE) start-dev --import-realm; \
		echo "Waiting for Keycloak..."; \
		until curl -sf http://localhost:$(KC_EXAMPLES_PORT)/realms/oneauth-examples > /dev/null 2>&1; do sleep 2; done; \
		echo "Keycloak ready at http://localhost:$(KC_EXAMPLES_PORT)"; \
		echo "  Realm: http://localhost:$(KC_EXAMPLES_PORT)/realms/oneauth-examples"; \
	fi

downkcl:
	@docker stop $(KC_EXAMPLES_CONTAINER) 2>/dev/null || echo "Not running"

.PHONY: walkthroughs demos-ci list upkcl downkcl
