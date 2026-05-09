# OIDF conformance harness

This directory wires the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against `cmd/oneauth-server` to produce a measured baseline of which OIDC certification tests OneAuth passes today.

**Status:** Phase 1 — manually-run baseline. Not yet wired into the [`tests/conformance/` ratchet](../conformance/README.md). See issue 197 for the longer-term plan.

## Quick start

```bash
# Terminal 1: start the harness (mongo + nginx + Java server)
make upoidf

# Terminal 2: start oneauth-server with the matching test config
make upoidf-as
```

UI: https://localhost.emobix.co.uk:8443/  (the hostname resolves publicly to 127.0.0.1, no `/etc/hosts` edit required).

OneAuth: `http://host.docker.internal:8888` (reachable from inside Docker on macOS).

When done:

```bash
make downoidf
# Ctrl-C the oneauth-server in Terminal 2.
```

## Running a baseline plan via the harness REST API

The UI is the easy path; the API is reproducible. Both work with the same harness instance.

```bash
# The simplest plan: discovery-only (no /authorize required).
cat > /tmp/oidf-config.json <<'EOF'
{
  "alias": "oneauth-config-baseline",
  "server": {
    "discoveryUrl": "http://host.docker.internal:8888/.well-known/openid-configuration"
  }
}
EOF

# Create plan instance
PLAN=$(curl -ks -X POST \
  "https://localhost.emobix.co.uk:8443/api/plan?planName=oidcc-config-certification-test-plan" \
  -H "Content-Type: application/json" --data @/tmp/oidf-config.json \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")

# Run the discovery test
TEST=$(curl -ks -X POST \
  "https://localhost.emobix.co.uk:8443/api/runner?test=oidcc-discovery-endpoint-verification&plan=${PLAN}&variant=%7B%22server_metadata%22%3A%22discovery%22%2C%22client_registration%22%3A%22static_client%22%7D" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")

# Pull the result
sleep 5
curl -ks "https://localhost.emobix.co.uk:8443/api/info/${TEST}" | python3 -m json.tool
curl -ks "https://localhost.emobix.co.uk:8443/api/log/${TEST}" | python3 -m json.tool
```

## Layout

```
tests/oidf-conformance/
├── README.md                        ← this file
├── docker-compose-prebuilt.yml      ← upstream OIDF compose (vendored)
├── oneauth-server.yaml              ← AS config the harness can target
├── baselines/
│   └── 2026-05-09/                  ← captured logs from the first baseline run
│       ├── BASELINE.md              ← human-readable summary
│       ├── config-cert-discovery.json
│       ├── config-cert-discovery.failures.txt
│       └── basic-op-oidcc-server.json
└── .gitignore                        ← excludes mongo/ runtime dir
```

## Why a separate vendored compose file

The upstream `docker-compose-prebuilt.yml` doesn't change frequently. Vendoring it (rather than `curl`-ing on every `make upoidf`) keeps the harness version pinnable per OneAuth release and lets `make upoidf` work offline once images are pulled.

To refresh it:

```bash
curl -O https://gitlab.com/openid/conformance-suite/-/raw/master/docker-compose-prebuilt.yml \
  -o tests/oidf-conformance/docker-compose-prebuilt.yml
```

## Networking notes

The harness runs in Docker; OneAuth runs on the host. They communicate via `host.docker.internal` (resolvable from inside Mac/Windows Docker containers automatically; on Linux CI a `--add-host=host.docker.internal:host-gateway` may be needed if we ever wire this into CI).

The harness expects HTTPS on the AS in production-mode plans. Phase 1 runs HTTP-only and accepts the resulting `Expected https protocol for ...` failures as known-deployment-mode warnings — they say nothing about spec compliance, only about how we're hosting locally. A follow-up will add a TLS-fronted variant for completeness.

## What's next (Phase 2)

- Wire results into `tests/conformance/`'s ratchet under the existing `suite + plan + test` external schema.
- Add a CI job (manual-trigger, like `testkcl`).
- Close the gaps catalogued in `baselines/<date>/BASELINE.md` one by one.
