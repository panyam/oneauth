# 08 — Rich Authorization Requests (RFC 9396)
#
# Infrastructure: None (RAR test issuer optional for cross-server demo)
#
# To see the cross-server step:
#   make uprar (from repo root) — starts RAR test issuer on port 8181

EXAMPLE_DIR := 08-rich-authorization-requests

run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

.PHONY: run demo readme
