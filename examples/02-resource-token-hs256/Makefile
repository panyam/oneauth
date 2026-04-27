# 02 — Resource Token with HS256 (Federated Auth)
#
# Infrastructure: None (in-memory, self-contained)

EXAMPLE_DIR := 02-resource-token-hs256

run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

.PHONY: run demo readme
