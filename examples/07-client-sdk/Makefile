# 07 — Client SDK: Production Patterns
#
# Infrastructure: None (Keycloak optional for cross-server demo)

EXAMPLE_DIR := 07-client-sdk

run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

upkcl:
	$(MAKE) -C .. upkcl

downkcl:
	$(MAKE) -C .. downkcl

.PHONY: run demo readme upkcl downkcl
