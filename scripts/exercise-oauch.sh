#!/usr/bin/env bash
# exercise-oauch.sh runs OAuch's test set against oneauth-server (issue 567):
#   1. build cmd/oneauth-server and start it with tests/oauch/oneauth-oauch.yaml
#      on :8895, as https://localhost.emobix.co.uk:8895
#   2. install playwright-go's driver and Chromium if they're missing
#   3. run tests/oauch's TestOAuch, which signs up a user, registers two
#      clients, drives OAuch's dashboard in Chromium, and checks the results
#      against tests/oauch/expected.yaml
#
# Needs OAuch on OAUCH_URL (make upoauch). The export of the run lands in
# test-reports/oauch/oauch-export.json for triage.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${OAUCH_URL:?set OAUCH_URL, or run make testoauch}"
as=https://localhost.emobix.co.uk:8895

work=$(mktemp -d)
server_log="$work/oneauth-server.log"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

go build -buildvcs=false -o "$work/oneauth-server" ./cmd/oneauth-server
"$work/oneauth-server" --config tests/oauch/oneauth-oauch.yaml >"$server_log" 2>&1 &
pids+=($!)
disown  # keeps bash from reporting the kill in cleanup
scripts/wait-for.sh 60 "oneauth-server (oauch)" --pid "${pids[0]}" --log "$server_log" -- \
  -k "$as/.well-known/openid-configuration" || exit 2

(cd tests/oauch && go run github.com/mxschmitt/playwright-go/cmd/playwright install chromium >/dev/null)

mkdir -p test-reports/oauch
cd tests/oauch
OAUCH_URL="$OAUCH_URL" OAUCH_AS_URL="$as" OAUCH_REPORT_DIR="$PWD/../../test-reports/oauch" \
  go test -v -count=1 -timeout 40m -run '^TestOAuch$' .
