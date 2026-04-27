# 06 — Dynamic Client Registration (RFC 7591)
#
# Infrastructure: None (Keycloak optional for cross-server DCR demo)
#
# To see the Keycloak step:
#   make upkcl    # start Keycloak for examples (port 8280)
#   make run      # the KC step auto-detects and runs

EXAMPLE_DIR := 06-dynamic-client-registration

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
