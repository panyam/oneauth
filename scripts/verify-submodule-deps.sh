#!/bin/bash
# Verifies that every published oneauth module points at one version of
# every other oneauth module, and that none of them can only build from a
# checkout.
#
# Rules, for each published module (the root plus PUBLISHED below):
#
#   1. No `replace github.com/panyam/oneauth...` directive. Go refuses
#      `go install <module>@<version>` for a module whose go.mod has one,
#      and consumers ignore them anyway. Local development uses go.work.
#   2. Every require of a github.com/panyam/oneauth* module, direct or
#      indirect, names EXPECTED: the version being released when RELEASING
#      is set (make release), otherwise the latest root tag.
#   3. go.work's release-managed replace block names EXPECTED too.
#   4. Outside a release, each published go.sum has EXPECTED's hashes, so
#      the module builds with GOWORK=off.
#
#   5. Each unpublished module (tests/*, docs/site) resolves with
#      GOWORK=off, so its oneauth requires haven't fallen behind.
#
# A release commit sets every such require to the version it is about to
# tag, so stores/gorm@vX requires oneauth@vX and cmd/oneauth-server@vX
# requires stores/gorm@vX. Between releases the requires keep naming the
# last tag, and go.work builds the checkout as one workspace.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Modules that are tagged and published. Test harnesses under tests/ and
# docs/site are not, and keep their replace directives.
PUBLISHED=(
    "stores/gorm"
    "stores/gae"
    "saml"
    "grpc"
    "oauth2"
    "sshkeys"
    "cmd/oneauth"
    "cmd/oneauth-server"
    "cmd/demo-hostapp"
    "cmd/demo-resource-server"
)

EXPECTED="${RELEASING:-}"
if [ -z "$EXPECTED" ]; then
    EXPECTED="$(cd "$REPO_ROOT" && git tag -l 'v*' --sort=-v:refname | head -1)"
fi
if [ -z "$EXPECTED" ]; then
    echo "FAIL: no root tag found and RELEASING not set"
    exit 1
fi

# Unpublished modules: every go.work module that is neither the root nor in
# PUBLISHED, such as tests/keycloak and docs/site. They aren't tagged, and
# they keep their replace directives. release.sh lists them the same way.
unpublished_modules() {
    awk '/^use[[:space:]]*\(/{f=1;next} f&&/^\)/{f=0} f{sub(/^\.\//,"",$1); print $1}' "$REPO_ROOT/go.work" |
        while read -r m; do
            [ -z "$m" ] || [ "$m" = "." ] && continue
            case " ${PUBLISHED[*]} " in *" $m "*) continue ;; esac
            echo "$m"
        done
}
if [ "${1:-}" = "--unpublished" ]; then
    unpublished_modules
    exit 0
fi

fail=0
for sub in "${PUBLISHED[@]}"; do
    gomod="$REPO_ROOT/$sub/go.mod"
    if [ ! -f "$gomod" ]; then
        echo "FAIL: $sub/go.mod not found"
        fail=1
        continue
    fi

    if grep -qE '^replace[[:space:]]+github\.com/panyam/oneauth|^[[:space:]]+github\.com/panyam/oneauth[^[:space:]]*[[:space:]]+=>' "$gomod"; then
        echo "FAIL: $sub/go.mod replaces a oneauth module; go install $sub@vX would be refused. Use go.work instead."
        fail=1
    fi

    # Every require line naming a oneauth module, single-line or in a block.
    while read -r module version; do
        [ -z "$module" ] && continue
        if [ "$version" != "$EXPECTED" ]; then
            echo "FAIL: $sub requires $module $version, want $EXPECTED"
            fail=1
        fi
    done < <(awk '
        /^require[[:space:]]+github\.com\/panyam\/oneauth[^[:space:]]*[[:space:]]+v/ { print $2, $3; next }
        /^require[[:space:]]*\(/ { inblock = 1; next }
        inblock && /^\)/ { inblock = 0; next }
        inblock && $1 ~ /^github\.com\/panyam\/oneauth/ { print $1, $2 }
    ' "$gomod")
done

# 4. Between releases, each published go.sum holds hashes for EXPECTED, so
#    the module builds outside the workspace. A release in progress
#    (RELEASING set) can't have them yet; record-release-sums.sh adds them
#    after the tags are pushed.
if [ -z "${RELEASING:-}" ]; then
    for sub in "${PUBLISHED[@]}"; do
        while read -r module; do
            [ -z "$module" ] && continue
            if ! grep -q "^$module $EXPECTED h1:" "$REPO_ROOT/$sub/go.sum" 2>/dev/null; then
                echo "FAIL: $sub/go.sum has no hash for $module $EXPECTED; run scripts/record-release-sums.sh $EXPECTED"
                fail=1
            fi
        done < <(awk -v v="$EXPECTED" '
            /^require[[:space:]]+github\.com\/panyam\/oneauth[^[:space:]]*[[:space:]]+v/ { print $2; next }
            /^require[[:space:]]*\(/ { inblock = 1; next }
            inblock && /^\)/ { inblock = 0; next }
            inblock && $1 ~ /^github\.com\/panyam\/oneauth/ && $0 !~ /\/\/ indirect/ { print $1 }
        ' "$REPO_ROOT/$sub/go.mod")
    done
fi

# 3. go.work's managed replace block maps EXPECTED to this checkout, so
#    the workspace builds even before EXPECTED is tagged.
if ! grep -q "github.com/panyam/oneauth $EXPECTED => ./" "$REPO_ROOT/go.work"; then
    echo "FAIL: go.work's release-managed replace block doesn't name $EXPECTED; run scripts/workspace-replace.sh $EXPECTED"
    fail=1
fi

# 5. Each unpublished module resolves its requirements under GOWORK=off
#    without editing go.mod. Such a module replaces oneauth modules with
#    this checkout, and a replaced published module can require a newer
#    oneauth than the unpublished module names. Go then stops with "updates
#    to go.mod needed", which broke make testkcl after v0.3.17 (issue 553).
#    release.sh bumps those requires, and this catches drift from any other
#    source. It doesn't use go mod tidy -diff, which also fails on stale
#    go.sum lines that do no harm.
for sub in $(unpublished_modules); do
    if ! out=$(cd "$REPO_ROOT/$sub" && GOWORK=off go list -mod=readonly -deps -test ./... 2>&1 >/dev/null); then
        echo "FAIL: $sub doesn't resolve with GOWORK=off:"
        echo "$out" | head -5 | sed 's/^/    /'
        fail=1
    fi
done

if [ $fail -ne 0 ]; then
    echo ""
    echo "Fix by hand, or cut a release with: make release V=vX.Y.Z"
    exit 1
fi
echo "All published modules require oneauth modules at $EXPECTED, with no replace directives."
echo "All unpublished modules resolve with GOWORK=off."
