#!/usr/bin/env bash
# Runs one OIDF conformance plan against cmd/oneauth-server. The plan is the
# first argument:
#
#   fapi2  fapi2-security-profile-final-test-plan, mission 98, on :8889
#          with tests/oidf-conformance/oneauth-fapi2.yaml
#   oidcc  oidcc-basic-certification-test-plan, mission 477, on :8890
#          with tests/oidf-conformance/oneauth-oidcc.yaml
#
#   1. start the OIDF harness (make upoidf) unless it's already up
#   2. start oneauth-server with the plan's config on https://localhost:<port>
#      (https://host.docker.internal:<port> from inside the harness
#      container), stopped again on exit
#   3. register the plan's user and clients, run every module, print results
#
# Each module is judged against tests/conformance/known-gaps.yaml, and the
# script exits non-zero on a regression or a stale entry. Further arguments
# go to tests/oidf-conformance/cmd/exercise (e.g. -module codereuse to run
# just matching modules).
#
# With --go-test after the plan, step 3 is instead the plan's ratchet test in
# tests/oidf-conformance (what `make testoidf` runs), and the remaining
# arguments go to go test. Server log: $OIDF_LOG (default
# /tmp/oneauth-<plan>-exercise.log).
set -euo pipefail
cd "$(dirname "$0")/.."

plan=${1:-}
case "$plan" in
  # The fapi2 run's go test covers the whole package (the discovery plan
  # and the scorecard too, as `make testoidf` always has); the oidcc run
  # covers only its own plan, since the rest already ran.
  fapi2) port=8889 config=tests/oidf-conformance/oneauth-fapi2.yaml gotest=. ;;
  oidcc) port=8890 config=tests/oidf-conformance/oneauth-oidcc.yaml gotest='^TestOIDF_OIDCC_BasicOP$' ;;
  *) echo "usage: $0 fapi2|oidcc [--go-test] [args...]" >&2; exit 2 ;;
esac
shift

harness=https://localhost.emobix.co.uk:8443
server=https://localhost:$port
ca=tests/oidf-conformance/certs/ca.crt
logfile=${OIDF_LOG:-/tmp/oneauth-$plan-exercise.log}

if ! curl -ksf -o /dev/null "$harness/"; then
  make upoidf
fi

if curl -sf --cacert "$ca" -o /dev/null "$server/.well-known/openid-configuration"; then
  echo "A server is already listening on $server. Stop it first: the exercise needs a fresh one." >&2
  exit 2
fi

go build -buildvcs=false -o "/tmp/oneauth-$plan-server" ./cmd/oneauth-server
"/tmp/oneauth-$plan-server" --config "$config" >"$logfile" 2>&1 &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT

# Fails if the server exits or hasn't answered within 60 seconds, rather
# than going on to drive a plan against nothing.
"$(dirname "$0")/wait-for.sh" 60 "oneauth-server ($plan)" --pid "$server_pid" --log "$logfile" -- \
  --cacert "$ca" "$server/.well-known/openid-configuration" || exit 2

if [[ "${1:-}" == --go-test ]]; then
  shift
  (cd tests/oidf-conformance && GOWORK=off go test -count=1 -v -timeout 90m -run "$gotest" ./... "$@")
  exit
fi

(cd tests/oidf-conformance && GOWORK=off go run ./cmd/exercise -plan "$plan" \
  -harness "$harness" -server "$server" -issuer "https://host.docker.internal:$port" \
  -ca certs/ca.crt "$@")
