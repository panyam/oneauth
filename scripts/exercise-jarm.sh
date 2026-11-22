#!/usr/bin/env bash
# Runs the JARM mission's exercise (issue 409): a headless
# `oneauth token browser --response-mode jwt` login against oneauth-server
# and against the test Keycloak realm.
#
#   1. build cmd/oneauth and cmd/oneauth-server
#   2. start oneauth-server with deploy-examples/jarm.yaml on :18500
#   3. run tests/keycloak/cmd/exercise-jarm, which drives the CLI against
#      the server and then against Keycloak on KC_PORT (default 8180), with
#      the CLI's callback on :18501
#
# For each target it prints the callback the CLI received (the decoded
# response JWT when there is one), then the token or the CLI's refusal,
# and a result line. A third run logs in to oneauth-server with one
# character of the response's signature flipped, which the CLI must
# refuse. It exits 1 when a target ends without a token or the tampered
# run gets one.
# `make exercise-jarm` starts Keycloak first. A Keycloak started before
# realm.json gained the test-jarm client needs `make downkcl`.
#
# MODE=<response_mode> overrides jwt. Server log: /tmp/oneauth-jarm-server.log.
set -euo pipefail
cd "$(dirname "$0")/.."

as_port=18500 callback_port=18501
kc_port=${KC_PORT:-8180}
as=http://localhost:$as_port
kc=http://localhost:$kc_port/realms/oneauth-test
for port in $as_port $callback_port; do
  if curl -s -o /dev/null "http://localhost:$port/"; then
    echo "Something is already listening on :$port. Stop it first." >&2
    exit 2
  fi
done
if ! curl -sf -o /dev/null "$kc/.well-known/openid-configuration"; then
  echo "No Keycloak realm at $kc. Run 'make upkcl KC_PORT=$kc_port' first." >&2
  exit 2
fi
probe="$kc/protocol/openid-connect/auth?client_id=test-jarm&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A$callback_port%2Fcallback"
if curl -s "$probe" | grep -qi "client not found"; then
  echo "Keycloak at $kc has no test-jarm client. It was started before realm.json changed: run 'make downkcl upkcl KC_PORT=$kc_port'." >&2
  exit 2
fi

work=$(mktemp -d)
server_log=/tmp/oneauth-jarm-server.log
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

go build -buildvcs=false -o "$work/oneauth-server" ./cmd/oneauth-server
go build -buildvcs=false -o "$work/oneauth" ./cmd/oneauth
(cd tests/keycloak && go build -buildvcs=false -o "$work/exercise-jarm" ./cmd/exercise-jarm)

JARM_AS_PORT=$as_port "$work/oneauth-server" --config cmd/oneauth-server/deploy-examples/jarm.yaml >"$server_log" 2>&1 &
pids+=($!)
disown  # keeps bash from reporting the kill in cleanup
scripts/wait-for.sh 60 "oneauth-server (jarm)" --pid "${pids[0]}" --log "$server_log" -- \
  "$as/.well-known/oauth-authorization-server" || exit 2

"$work/exercise-jarm" -cli "$work/oneauth" -as "$as" -keycloak "$kc" \
  -callback-port $callback_port -response-mode "${MODE:-jwt}"
