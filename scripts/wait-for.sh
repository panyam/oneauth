#!/usr/bin/env bash
# wait-for.sh <seconds> <what> [--pid PID] [--log FILE] -- <curl args...>
#
# Polls `curl -sf <curl args>` once a second until it succeeds, and fails
# with a message after <seconds>. With --pid, it fails as soon as that
# process exits, and with --log it prints the log's last lines when it
# fails. Every wait for a container or server in the Makefile goes through
# this, so a service that never comes up stops the target with a reason
# instead of hanging it (mission 489).
set -uo pipefail

limit="$1"; what="$2"; shift 2
pid=""; log=""
while [[ $# -gt 0 && "$1" != "--" ]]; do
  case "$1" in
    --pid) pid="$2"; shift 2 ;;
    --log) log="$2"; shift 2 ;;
    *) echo "wait-for.sh: unknown option $1" >&2; exit 2 ;;
  esac
done
[[ "${1:-}" == "--" ]] && shift

show_log() {
  if [[ -n "$log" && -f "$log" ]]; then
    echo "--- last lines of $log:" >&2
    tail -n 20 "$log" >&2
  fi
}

for ((i = 0; i < limit; i++)); do
  if curl -sf -o /dev/null "$@" 2>/dev/null; then
    exit 0
  fi
  if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
    echo "$what exited before answering." >&2
    show_log
    exit 1
  fi
  sleep 1
done
echo "$what did not answer within ${limit}s." >&2
show_log
exit 1
