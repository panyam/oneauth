# 09-key-rotation

EXAMPLE_DIR := 09-key-rotation

run:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/

demo:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --non-interactive

readme:
	cd ../.. && go run -buildvcs=false ./examples/$(EXAMPLE_DIR)/ --readme > examples/$(EXAMPLE_DIR)/README.md

.PHONY: run demo readme
