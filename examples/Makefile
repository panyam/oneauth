# Examples top-level Makefile
#
# Batch operations across all examples. Per-example commands
# (run, demo, readme) live in each example's own Makefile.

EXAMPLES := $(sort $(wildcard [0-9][0-9]-*/))

# Generate README.md for every example that has Go files.
readmes:
	@count=0; for dir in $(EXAMPLES); do \
		if ls $$dir/*.go >/dev/null 2>&1; then \
			echo "[readme] $$dir"; \
			$(MAKE) -C $$dir readme; \
			count=$$((count + 1)); \
		else \
			echo "[skip]   $$dir (no Go files yet)"; \
		fi; \
	done; \
	echo "Done. Generated $$count READMEs."

# List all examples.
list:
	@for dir in $(EXAMPLES); do \
		echo "  $$dir"; \
	done

.PHONY: readmes list
