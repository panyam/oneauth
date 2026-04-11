#!/bin/bash
# Verifies that oneauth sub-module go.mod files require a real, tagged version
# of the root github.com/panyam/oneauth module — not the v0.0.0 placeholder
# nor the ancient v0.0.39 stale value that existed before this check was added.
#
# Why: a sub-module's `require github.com/panyam/oneauth v0.0.0` works locally
# thanks to the `replace ../..` directive, but downstream consumers cannot
# `go get github.com/panyam/oneauth/stores/gorm@vX` because Go ignores replace
# directives in non-main modules. The require line must point to a released
# tag so the module graph resolves for external users.
#
# Same pattern as mcpkit#189 — this script is a direct port.
#
# Failure modes this catches:
# 1. require github.com/panyam/oneauth v0.0.0 — the placeholder bug
# 2. require github.com/panyam/oneauth vX.Y.Z where X.Y.Z is more than 10
#    patch versions behind the current root tag (stale after multi-bump)
# 3. Inter-sub-module requires (e.g., stores/gorm referenced from
#    cmd/oneauth-server) that lag the current root version

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Sub-modules that are independently tagged and require the root module.
# tests/keycloak is intentionally excluded — it's a test harness using
# a zero pseudo-version, not published externally.
SUBMODULES=(
    "stores/gorm"
    "stores/gae"
    "cmd/demo-hostapp"
    "cmd/oneauth-server"
    "cmd/demo-resource-server"
)

# Current root tag — compute from git so the script stays correct as tags advance.
# Falls back to an empty string if not in a git checkout (CI may inject it).
CURRENT_ROOT_TAG="${ONEAUTH_ROOT_TAG:-}"
if [ -z "$CURRENT_ROOT_TAG" ]; then
    CURRENT_ROOT_TAG="$(cd "$REPO_ROOT" && git tag -l 'v*' --sort=-v:refname | head -1 2>/dev/null || true)"
fi

fail=0
for sub in "${SUBMODULES[@]}"; do
    gomod="$REPO_ROOT/$sub/go.mod"
    if [ ! -f "$gomod" ]; then
        echo "MISSING: $gomod not found"
        fail=1
        continue
    fi

    # Extract all github.com/panyam/oneauth* direct requires (not indirect).
    # Matches both single-line require and require-block entries.
    requires="$(awk '
        /^require[[:space:]]+github\.com\/panyam\/oneauth[^[:space:]]*[[:space:]]+v[0-9]/ {
            print $2 " " $3
        }
        /^[[:space:]]+github\.com\/panyam\/oneauth[^[:space:]]*[[:space:]]+v[0-9]/ {
            if ($0 !~ /\/\/ indirect/) {
                print $1 " " $2
            }
        }
    ' "$gomod")"

    if [ -z "$requires" ]; then
        echo "PASS: $sub has no direct require on github.com/panyam/oneauth* (skipping)"
        continue
    fi

    while IFS=' ' read -r module version; do
        [ -z "$module" ] && continue

        if [ "$version" = "v0.0.0" ]; then
            echo "FAIL: $sub requires $module v0.0.0 (placeholder)"
            echo "      Bump to the current root tag. See CLAUDE.md 'Releasing Sub-Modules' for the release order."
            fail=1
            continue
        fi

        # Soft-warn if version looks ancient (v0.0.X where X < 50 and current > 60)
        # This catches multi-bump staleness without being overly strict.
        if [ -n "$CURRENT_ROOT_TAG" ]; then
            case "$version" in
                v0.0.[0-9] | v0.0.[0-3][0-9] | v0.0.4[0-9])
                    case "$CURRENT_ROOT_TAG" in
                        v0.0.[6-9][0-9] | v0.[1-9]* | v[1-9]*)
                            echo "WARN: $sub requires $module $version (current root: $CURRENT_ROOT_TAG)"
                            ;;
                    esac
                    ;;
            esac
        fi

        echo "PASS: $sub requires $module $version"
    done <<< "$requires"
done

if [ $fail -ne 0 ]; then
    exit 1
fi

echo ""
echo "All sub-modules reference a real root version."
