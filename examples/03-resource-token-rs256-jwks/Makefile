# 03 — Resource Token with RS256 + JWKS Discovery
#
# Infrastructure: None (in-memory, self-contained)

EXAMPLE_DIR := 03-resource-token-rs256-jwks

run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

.PHONY: run demo readme
