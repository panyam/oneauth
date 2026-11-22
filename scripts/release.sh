#!/bin/bash
# Cuts release V across every oneauth module, as one release commit.
#
#   1. Checks main is clean, matches origin/main, and V is not tagged yet.
#   2. Sets every github.com/panyam/oneauth* require in every published
#      go.mod to V. That version doesn't exist until step 5, which is fine:
#      the workspace (go.work) builds the checkout, and consumers fetch the
#      tags after they are pushed. The unpublished modules' oneauth
#      requires move to V as well.
#      workspace-replace.sh maps V to this checkout in go.work, since Go
#      reads a workspace module's go.mod at the required version.
#   3. Runs verify-submodule-deps with RELEASING=V and builds every module
#      in the workspace.
#   4. Commits "Release V".
#   5. Tags the root and every sub-module on that commit (make tag).
#
# Nothing is pushed. `make pushrelease V=...` pushes main and the tags, and
# `make verify-install V=...` then checks `go install` of the commands.

set -euo pipefail
V="${1:?usage: release.sh vX.Y.Z}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

[[ "$V" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must look like v1.2.3, got $V"; exit 1; }
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || { echo "release from main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean"; exit 1; }
git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "main is not at origin/main; pull first"; exit 1; }
if git rev-parse -q --verify "refs/tags/$V" >/dev/null; then echo "$V is already tagged"; exit 1; fi

PUBLISHED=$(awk '/^PUBLISHED=\(/{f=1;next} f&&/^\)/{f=0} f{gsub(/[" ]/,""); print}' scripts/verify-submodule-deps.sh)
for mod in $PUBLISHED; do
    for dep in $(cd "$mod" && go mod edit -json | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(r["Path"] for r in (d.get("Require") or []) if r["Path"].startswith("github.com/panyam/oneauth")))'); do
        (cd "$mod" && go mod edit -require="$dep@$V")
    done
done

# Unpublished modules (tests/*, docs/site) replace oneauth modules with this
# checkout. A replaced published module now requires V, so each oneauth
# require naming a release moves to V too, or GOWORK=off runs there stop at
# "updates to go.mod needed" (issue 553). The v0.0.0 placeholder some of
# them use beside a replace isn't a release, and stays.
for mod in $(bash scripts/verify-submodule-deps.sh --unpublished); do
    for dep in $(cd "$mod" && go mod edit -json | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(r["Path"] for r in (d.get("Require") or []) if r["Path"].startswith("github.com/panyam/oneauth") and not r["Version"].startswith("v0.0.0-")))'); do
        (cd "$mod" && go mod edit -require="$dep@$V")
    done
done

bash scripts/workspace-replace.sh "$V"
RELEASING="$V" bash scripts/verify-submodule-deps.sh
go build ./...
for mod in $PUBLISHED; do (cd "$mod" && go build ./...); done

git commit -qam "Release $V"
make -s tag V="$V"
echo ""
echo "Release commit and tags for $V are local. Push with: make pushrelease V=$V"
