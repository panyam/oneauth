# 01 — Client Credentials Flow
#
# Two-process architecture: main.go boots an auth server (--serve mode)
# that any OAuth client can drive. The walkthrough is one such client.

EXAMPLE_DIR := 01-client-credentials

# Default: run the walkthrough interactively (TUI renderer).
demo: ## Run the demokit walkthrough (interactive, TUI)
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --tui

# Plain renderer (for piping / CI).
demo-plain: ## Run the walkthrough with the plain renderer
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

# Non-interactive — fire every step without pausing.
demo-ci: ## Run the walkthrough non-interactively (no pauses)
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

# Run just the auth server + resource server on real ports. Use this
# when driving the example from curl, your own client, or a different
# walkthrough binary.
serve: ## Start auth server (:8081) + resource server (:8082) and block
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --serve

# Regenerate WALKTHROUGH.md from the demo definition.
walkthrough: ## Regenerate WALKTHROUGH.md (mermaid + steps + run-it commands)
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --doc md > examples/$(EXAMPLE_DIR)/WALKTHROUGH.md

.PHONY: demo demo-plain demo-ci serve walkthrough
.DEFAULT_GOAL := demo
