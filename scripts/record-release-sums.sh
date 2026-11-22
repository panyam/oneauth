#!/bin/bash
# Records go.sum hashes for release V in every published module, after
# V's tags are pushed.
#
# Why: a release commit sets every oneauth require to V before V exists,
# so it can't carry V's hashes. go install <cmd>@V and the workspace don't
# need them, but any build of a published module outside the workspace
# (GOWORK=off, as `make vulncheck` scans each module) does, and fails
# with "missing go.sum entry" until they are recorded.
#
# Waits for the module proxy to serve V, runs GOWORK=off go mod tidy in
# each published module, checks each builds standalone, and commits the
# result as "Record V module sums". Nothing is pushed.

set -euo pipefail
V="${1:?usage: record-release-sums.sh vX.Y.Z}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PUBLISHED=$(awk '/^PUBLISHED=\(/{f=1;next} f&&/^\)/{f=0} f{gsub(/[" ]/,""); print}' scripts/verify-submodule-deps.sh)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for i in $(seq 1 30); do
    if (cd "$tmp" && GOWORK=off GOFLAGS= go list -m "github.com/panyam/oneauth@$V" >/dev/null 2>&1); then
        break
    fi
    [ "$i" = 30 ] && { echo "proxy doesn't serve github.com/panyam/oneauth@$V yet; rerun later"; exit 1; }
    sleep 10
done

for mod in $PUBLISHED; do
    (cd "$mod" && GOWORK=off go mod tidy)
done
for mod in $PUBLISHED; do
    (cd "$mod" && GOWORK=off go build ./...)
done

if [ -n "$(git status --porcelain -- '*go.sum' '*go.mod')" ]; then
    git add -- $(git ls-files -m '*go.sum' '*go.mod')
    git commit -qm "Record $V module sums"
    echo "Committed $V module sums."
else
    echo "Sums for $V were already recorded."
fi
