# 05 — Token Introspection (RFC 7662)
#
# Infrastructure: None (Keycloak optional for cross-server introspection demo)
#
# To see the Keycloak step:
#   make upkcl    # start Keycloak for examples (port 8280)
#   make run      # the KC step auto-detects and runs

EXAMPLE_DIR := 05-introspection

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
