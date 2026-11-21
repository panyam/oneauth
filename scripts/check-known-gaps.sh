#!/usr/bin/env bash
# Checks that every `class: open` entry in tests/conformance/known-gaps.yaml
# names an open GitHub issue (mission 489). An open gap with a closed issue
# is either fixed, and its entry should go, or accepted, and its class should
# say so. `accepted` entries may cite closed issues: that is where the
# decision was made.
#
# Needs gh, authenticated through GH_TOKEN or GITHUB_TOKEN. The nightly
# conformance workflow runs it, and `make gapcheck` runs it locally.
set -euo pipefail
cd "$(dirname "$0")/.."
manifest=tests/conformance/known-gaps.yaml
repo=${GITHUB_REPOSITORY:-panyam/oneauth}

# One "class issue" pair per entry, in file order.
pairs=$(awk '
  /^- suite:/ { if (c != "") print c, i; c = ""; i = "" }
  /^  class:/ { c = $2 }
  /^  issue:/ { i = $2 }
  END { if (c != "") print c, i }
' "$manifest")

bad=0
for issue in $(awk '$1 == "open" { print $2 }' <<<"$pairs" | sort -un); do
  state=$(gh issue view "$issue" -R "$repo" --json state -q .state)
  if [[ "$state" != OPEN ]]; then
    echo "known-gaps.yaml: issue $issue is $state, but open-class entries still cite it." >&2
    echo "  Remove the entries if the gap is fixed, or make them class: accepted with the reason." >&2
    bad=1
  fi
done
n_open=$(awk '$1 == "open"' <<<"$pairs" | wc -l | tr -d ' ')
n_accepted=$(awk '$1 == "accepted"' <<<"$pairs" | wc -l | tr -d ' ')
echo "known-gaps.yaml: $n_open open (each on an open issue: $([[ $bad == 0 ]] && echo yes || echo no)), $n_accepted accepted"
exit $bad
