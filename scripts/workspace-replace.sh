#!/bin/bash
# Rewrites the managed replace block in go.work so every published oneauth
# module at version V resolves to this checkout.
#
# Why: published go.mod files carry no replace directives (go install
# refuses them), and a release commit makes them require a version that is
# only tagged afterwards. Go still reads the go.mod of a workspace module at
# the required version, so without this block the workspace can't build the
# release commit before its tags exist. A replace pinned to one version is
# allowed for workspace modules where an unversioned one is not.

set -euo pipefail
V="${1:?usage: workspace-replace.sh vX.Y.Z}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO_ROOT/go.work"

PUBLISHED=$(awk '/^PUBLISHED=\(/{f=1;next} f&&/^\)/{f=0} f{gsub(/[" ]/,""); print}' "$REPO_ROOT/scripts/verify-submodule-deps.sh")

python3 -I - "$WORK" "$V" $PUBLISHED <<'PY'
import sys
work, v, mods = sys.argv[1], sys.argv[2], sys.argv[3:]
begin = "// BEGIN release-managed replaces (scripts/workspace-replace.sh)"
end = "// END release-managed replaces"
s = open(work).read()
if begin in s:
    s = s[:s.index(begin)].rstrip("\n") + s[s.index(end) + len(end):]
    s = s.rstrip("\n") + "\n"
lines = [f"\tgithub.com/panyam/oneauth {v} => ./"]
lines += [f"\tgithub.com/panyam/oneauth/{m} {v} => ./{m}" for m in sorted(mods)]
s += "\n" + begin + "\nreplace (\n" + "\n".join(lines) + "\n)\n" + end + "\n"
open(work, "w").write(s)
PY
