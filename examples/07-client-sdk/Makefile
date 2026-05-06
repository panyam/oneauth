# 07 — Client SDK: Production Patterns

EXAMPLE_DIR := 07-client-sdk

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

upkcl:
	$(MAKE) -C .. upkcl

downkcl:
	$(MAKE) -C .. downkcl

.PHONY: demo demo-plain demo-ci serve walkthrough upkcl downkcl
.DEFAULT_GOAL := demo
