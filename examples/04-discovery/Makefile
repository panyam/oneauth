# 04 — AS Metadata Discovery (RFC 8414)
#
# Infrastructure: None (Keycloak optional for cross-server discovery demo)
#
# To see the Keycloak comparison step:
#   make upkcl    # start Keycloak for examples (port 8280)
#   make run      # the KC step auto-detects and runs

EXAMPLE_DIR := 04-discovery

run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

# Start/stop Keycloak for this example (delegates to top-level examples Makefile)
upkcl:
	$(MAKE) -C .. upkcl

downkcl:
	$(MAKE) -C .. downkcl

.PHONY: run demo readme upkcl downkcl
