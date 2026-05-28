# 10 — Security: Attack Prevention

EXAMPLE_DIR := 10-security

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --tui

demo-plain:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo-ci:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

# Cell-based notebook UI (demokit/notebookbridge). Good for
# step-through-and-explore demos with persistent output cells.
note:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --mode=notebook

serve:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --serve

walkthrough:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --doc md > examples/$(EXAMPLE_DIR)/WALKTHROUGH.md

.PHONY: demo demo-plain demo-ci serve walkthrough note
.DEFAULT_GOAL := demo
