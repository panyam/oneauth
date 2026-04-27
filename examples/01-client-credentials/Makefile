# 01 — Client Credentials Flow
#
# Infrastructure: None (in-memory, self-contained)

EXAMPLE_DIR := 01-client-credentials

# Run interactively — pause between steps
run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

# Run non-interactively — full output, no pauses
demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

# Regenerate README.md from the code (single source of truth)
readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

.PHONY: run demo readme
