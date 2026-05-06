# 03 — Resource Token with RS256 + JWKS Discovery

EXAMPLE_DIR := 03-resource-token-rs256-jwks

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --tui

demo-plain:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo-ci:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

serve:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --serve

walkthrough:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --doc md > examples/$(EXAMPLE_DIR)/WALKTHROUGH.md

.PHONY: demo demo-plain demo-ci serve walkthrough
.DEFAULT_GOAL := demo
