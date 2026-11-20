#!/usr/bin/env bash
# Runs the MCP server-auth conformance scenarios against cmd/oneauth-server
# through one MCP SDK (issue 495). The SDK is the first argument:
#
#   gosdk   the official Go SDK, with oneauth's APIMiddleware as its auth
#   mcpkit  mcpkit, with its own ext/auth layer
#   ts      the official TypeScript SDK, with its own bearer middleware;
#           oneauth-server is the AS only, so this run checks interop
#
#   1. check out the conformance framework at MCPCONFORMANCE_REF, the
#      server auth scenarios on panyam/mcpconformance's pending branch
#      (upstream has none yet), into MCPCONFORMANCE_DIR
#   2. generate a signing key, start oneauth-server with
#      tests/mcpauth/oneauth-mcp.yaml on :18200
#   3. start the SDK's fixture from tests/mcpauth/cmd on :18300, which
#      registers a client and mints its tokens
#   4. run every auth scenario and judge each check against
#      tests/conformance/known-gaps.yaml (suite mcp, plan mcp-auth-<sdk>)
#
# Needs git, node and npx. Logs: /tmp/oneauth-mcpauth-<sdk>-{server,fixture}.log.
set -euo pipefail
cd "$(dirname "$0")/.."
sdk=${1:-}
case "$sdk" in
  gosdk|mcpkit|ts) ;;
  *) echo "usage: $0 gosdk|mcpkit|ts" >&2; exit 2 ;;
esac
for tool in git node npx openssl; do
  command -v "$tool" >/dev/null || { echo "exercise-mcpauth: $tool is required" >&2; exit 2; }
done

ref=${MCPCONFORMANCE_REF:-0b17b48a6d585b279833601c5a6f8d57eca9533b}
conf=${MCPCONFORMANCE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/oneauth/mcpconformance}
if [[ ! -d "$conf/.git" ]]; then
  git clone --quiet https://github.com/panyam/mcpconformance.git "$conf"
fi
if [[ "$(git -C "$conf" rev-parse HEAD)" != "$ref" ]]; then
  git -C "$conf" fetch --quiet origin
  git -C "$conf" checkout --quiet --detach "$ref"
fi
# Reinstall only when the lockfile changed since the last install.
stamp="$conf/node_modules/.oneauth-lock"
if [[ ! -f "$stamp" ]] || ! cmp -s "$conf/package-lock.json" "$stamp"; then
  (cd "$conf" && npm ci --silent --ignore-scripts)
  cp "$conf/package-lock.json" "$stamp"
fi

as_port=18200 fixture_port=18300
as=http://localhost:$as_port
mcp=http://localhost:$fixture_port/mcp
for port in $as_port $fixture_port; do
  if curl -s -o /dev/null "http://localhost:$port/"; then
    echo "Something is already listening on :$port. Stop it first." >&2
    exit 2
  fi
done

work=$(mktemp -d)
server_log=/tmp/oneauth-mcpauth-$sdk-server.log
fixture_log=/tmp/oneauth-mcpauth-$sdk-fixture.log
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/signing.pem" 2>/dev/null
# The upstream IdP oneauth-server trusts for jwt-bearer and token exchange.
idp_issuer=https://idp.mcpauth.test
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/idp.pem" 2>/dev/null
openssl pkey -in "$work/idp.pem" -pubout -out "$work/idp.pub.pem" 2>/dev/null
go build -buildvcs=false -o "$work/oneauth-server" ./cmd/oneauth-server
if [[ "$sdk" == ts ]]; then
  ts=tests/mcpauth/ts-fixture
  ts_stamp="$ts/node_modules/.oneauth-lock"
  if [[ ! -f "$ts_stamp" ]] || ! cmp -s "$ts/package-lock.json" "$ts_stamp"; then
    (cd "$ts" && npm ci --silent --ignore-scripts)
    cp "$ts/package-lock.json" "$ts_stamp"
  fi
  go build -buildvcs=false -o "$work/bootstrap" ./tests/mcpauth/cmd/bootstrap
else
  go build -buildvcs=false -o "$work/fixture" "./tests/mcpauth/cmd/$sdk-fixture"
fi

MCPAUTH_AS_PORT=$as_port MCPAUTH_SIGNING_KEY="$work/signing.pem" MCPAUTH_AUDIENCE=$mcp \
  MCPAUTH_IDP_ISSUER=$idp_issuer MCPAUTH_IDP_PUBKEY="$work/idp.pub.pem" \
  "$work/oneauth-server" --config tests/mcpauth/oneauth-mcp.yaml >"$server_log" 2>&1 &
pids+=($!)
scripts/wait-for.sh 60 "oneauth-server (mcpauth)" --pid "${pids[0]}" --log "$server_log" -- \
  "$as/.well-known/oauth-authorization-server" || exit 2

if [[ "$sdk" == ts ]]; then
  "$work/bootstrap" -as "$as" -mcp-url "$mcp" -key "$work/signing.pem" \
    -idp-key "$work/idp.pem" -idp-issuer "$idp_issuer" >"$work/tokens.json"
  (cd "$ts" && PORT=$fixture_port AS_URL=$as MCP_URL=$mcp BOOTSTRAP_FILE="$work/tokens.json" \
    exec npx tsx server.ts) >"$fixture_log" 2>&1 &
else
  "$work/fixture" -addr ":$fixture_port" -as "$as" -mcp-url "$mcp" -key "$work/signing.pem" \
    -idp-key "$work/idp.pem" -idp-issuer "$idp_issuer" >"$fixture_log" 2>&1 &
fi
pids+=($!)
scripts/wait-for.sh 60 "$sdk fixture" --pid "${pids[1]}" --log "$fixture_log" -- \
  "http://localhost:$fixture_port/demo/bootstrap" || exit 2

(cd tests/mcpauth && GOWORK=off go run ./cmd/exercise -sdk "$sdk" -conformance "$conf" -driver "$PWD/driver/run-auth.ts" \
  -fixture "http://localhost:$fixture_port" -as "$as" -manifest ../conformance/known-gaps.yaml)
