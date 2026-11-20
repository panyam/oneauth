# Conformance orchestration (mission 489). `make conformance` at the repo
# root runs `test` here. Each conf-<name> target delegates to the suite's
# own target in the root Makefile, so suites keep one definition, and each
# has an entry in suites.yaml (the drift check enforces that).
#
#   make -C conformance test            # every suite, one line each
#   make -C conformance test SUITE=x    # one suite
#   make -C conformance conf-<name>     # run a suite's target directly
#   make -C conformance report          # re-render REPORT.md from report.json

ROOT := ..

.PHONY: test report conf-native conf-oidf-config conf-oidf-fapi2 conf-oidf-basic-op conf-oidf-formpost-basic conf-oidf-dynamic-op conf-oidf-dynamic-id-token conf-oidf-dynamic-id-token-token \
	conf-oidf-tp-post conf-oidf-tp-secret-jwt conf-oidf-tp-private-key-jwt conf-mcp-auth-gosdk conf-mcp-auth-mcpkit conf-mcp-auth-ts conf-keycloak conf-authlete

RUNNER = cd $(ROOT)/tests/conformance && GOWORK=off go run ./cmd/suites \
		-registry ../../conformance/suites.yaml \
		-report-json ../../docs/conformance/report.json \
		-report-md ../../docs/conformance/REPORT.md

# Runs the suites, then merges the results into docs/conformance/report.json
# and renders docs/conformance/REPORT.md (the docsite's Conformance report).
test:
	$(RUNNER) -make-dir ../../conformance -logs ../../test-reports/conformance $(if $(SUITE),-suite $(SUITE))

# Re-renders REPORT.md from report.json, running nothing.
report:
	$(RUNNER) -render-only

conf-native:
	$(MAKE) -C $(ROOT) testconformance

conf-oidf-config:
	$(MAKE) -C $(ROOT) testoidf-config

conf-oidf-fapi2:
	$(MAKE) -C $(ROOT) exercise-fapi2

conf-oidf-basic-op:
	$(MAKE) -C $(ROOT) exercise-oidcc

conf-oidf-formpost-basic:
	$(MAKE) -C $(ROOT) exercise-oidccfp

conf-oidf-dynamic-op:
	$(MAKE) -C $(ROOT) exercise-oidcdyn

conf-oidf-dynamic-id-token:
	$(MAKE) -C $(ROOT) exercise-oidcdyn RESPONSE_TYPE=id_token

conf-oidf-dynamic-id-token-token:
	$(MAKE) -C $(ROOT) exercise-oidcdyn RESPONSE_TYPE="id_token token"

conf-oidf-tp-post:
	$(MAKE) -C $(ROOT) exercise-oidcctp AUTH=client_secret_post

conf-oidf-tp-secret-jwt:
	$(MAKE) -C $(ROOT) exercise-oidcctp AUTH=client_secret_jwt

conf-oidf-tp-private-key-jwt:
	$(MAKE) -C $(ROOT) exercise-oidcctp AUTH=private_key_jwt

conf-keycloak:
	$(MAKE) -C $(ROOT) testkcl

conf-mcp-auth-gosdk:
	$(MAKE) -C $(ROOT) exercise-mcpauth SDK=gosdk

conf-mcp-auth-mcpkit:
	$(MAKE) -C $(ROOT) exercise-mcpauth SDK=mcpkit

conf-mcp-auth-ts:
	$(MAKE) -C $(ROOT) exercise-mcpauth SDK=ts

conf-authlete:
	$(MAKE) -C $(ROOT) testauthlete
