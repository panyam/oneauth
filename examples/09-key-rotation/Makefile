# 09 — Key Rotation with Grace Periods

EXAMPLE_DIR := 09-key-rotation

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
