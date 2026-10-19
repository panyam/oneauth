#!/usr/bin/env bash
# The FAPI 2.0 mission's exercise (issue 98): run the OIDF
# fapi2-security-profile-final-test-plan against cmd/oneauth-server.
#
#   1. start the OIDF harness (make upoidf) unless it's already up
#   2. start oneauth-server with tests/oidf-conformance/oneauth-fapi2.yaml
#      on https://localhost:8889 (https://host.docker.internal:8889 from
#      inside the harness container), stopped again on exit
#   3. register a user and two clients, run every module, print results
#
# Each module is judged against tests/conformance/known-gaps.yaml, and the
# script exits non-zero on a regression or a stale entry. Arguments go to
# fapi2/cmd/exercise (e.g. -module reuse-request_uri to run just matching
# modules).
#
# With --go-test as the first argument, step 3 is instead `go test ./...` in
# tests/oidf-conformance, the ratchet `make testoidf` runs, and the remaining
# arguments go to go test. Server log: $OIDF_FAPI2_LOG (default
# /tmp/oneauth-fapi2-exercise.log).
set -euo pipefail
cd "$(dirname "$0")/.."

harness=https://localhost.emobix.co.uk:8443
server=https://localhost:8889
ca=tests/oidf-conformance/certs/ca.crt
logfile=${OIDF_FAPI2_LOG:-/tmp/oneauth-fapi2-exercise.log}

if ! curl -ksf -o /dev/null "$harness/"; then
  make upoidf
fi

if curl -sf --cacert "$ca" -o /dev/null "$server/.well-known/openid-configuration"; then
  echo "A server is already listening on $server. Stop it first: the exercise needs a fresh one." >&2
  exit 2
fi

go build -buildvcs=false -o /tmp/oneauth-fapi2-server ./cmd/oneauth-server
/tmp/oneauth-fapi2-server --config tests/oidf-conformance/oneauth-fapi2.yaml >"$logfile" 2>&1 &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -sf --cacert "$ca" -o /dev/null "$server/.well-known/openid-configuration" && break
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "oneauth-server exited at startup; log follows:" >&2
    cat "$logfile" >&2
    exit 2
  fi
  sleep 1
done

if [[ "${1:-}" == --go-test ]]; then
  shift
  (cd tests/oidf-conformance && GOWORK=off go test -count=1 -v -timeout 90m ./... "$@")
  exit
fi

(cd tests/oidf-conformance && GOWORK=off go run ./fapi2/cmd/exercise \
  -harness "$harness" -server "$server" -issuer https://host.docker.internal:8889 \
  -ca certs/ca.crt "$@")
