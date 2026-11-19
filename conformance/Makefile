# Conformance orchestration (mission 489). `make conformance` at the repo
# root runs `test` here. Each conf-<name> target delegates to the suite's
# own target in the root Makefile, so suites keep one definition, and each
# has an entry in suites.yaml (the drift check enforces that).
#
#   make -C conformance test            # every suite, one line each
#   make -C conformance test SUITE=x    # one suite
#   make -C conformance conf-<name>     # run a suite's target directly

ROOT := ..

.PHONY: test conf-native conf-oidf-config conf-oidf-fapi2 conf-oidf-basic-op conf-keycloak conf-authlete

test:
	cd $(ROOT)/tests/conformance && GOWORK=off go run ./cmd/suites \
		-registry ../../conformance/suites.yaml \
		-make-dir ../../conformance \
		-logs ../../test-reports/conformance \
		$(if $(SUITE),-suite $(SUITE))

conf-native:
	$(MAKE) -C $(ROOT) testconformance

conf-oidf-config:
	$(MAKE) -C $(ROOT) testoidf-config

conf-oidf-fapi2:
	$(MAKE) -C $(ROOT) exercise-fapi2

conf-oidf-basic-op:
	$(MAKE) -C $(ROOT) exercise-oidcc

conf-keycloak:
	$(MAKE) -C $(ROOT) testkcl

conf-authlete:
	$(MAKE) -C $(ROOT) testauthlete
