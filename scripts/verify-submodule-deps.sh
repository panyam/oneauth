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

# 3. go.work's managed replace block maps EXPECTED to this checkout, so
#    the workspace builds even before EXPECTED is tagged.
if ! grep -q "github.com/panyam/oneauth $EXPECTED => ./" "$REPO_ROOT/go.work"; then
    echo "FAIL: go.work's release-managed replace block doesn't name $EXPECTED; run scripts/workspace-replace.sh $EXPECTED"
    fail=1
fi

if [ $fail -ne 0 ]; then
    echo ""
    echo "Fix by hand, or cut a release with: make release V=vX.Y.Z"
    exit 1
fi
echo "All published modules require oneauth modules at $EXPECTED, with no replace directives."
