#!/usr/bin/env bash
# Verifies the security guarantees claimed by scripts/demo.sh.
# Usage: ./scripts/verify-demo.sh [demo.log]
# Read-only: parses the log, never runs a workload.
set -euo pipefail
log=${1:-demo.log}
if [ ! -r "$log" ]; then
  echo "FAIL cannot read $log (run: make demo 2>&1 | tee demo.log)" >&2
  exit 2
fi

clean=$(mktemp)
trap 'rm -f "$clean"' EXIT
# Portable ANSI escape stripping (GNU and BSD sed).
esc=$(printf '\033')
sed "s/${esc}\\[[0-9;]*m//g" "$log" > "$clean"

fail=0
section() {
  awk -v want="$1" '
    /^== [0-9]+\./ { on = ($0 ~ "^== " want "\\.") }
    on
  ' "$clean"
}
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
check() {
  if printf '%s\n' "$2" | grep -qF -- "$3"; then ok "$1"; else bad "$1 (missing: $3)"; fi
}
check_re() {
  if printf '%s\n' "$2" | grep -Eq -- "$3"; then ok "$1"; else bad "$1 (no match: $3)"; fi
}
check_blocked() {
  if printf '%s\n' "$2" | grep -Eq -- "BLOCKED.*$3"; then
    ok "$1"
  else
    bad "$1 (no BLOCKED line for: $3)"
  fi
}

s1=$(section 1); s2=$(section 2); s3=$(section 3)
s4=$(section 4); s5=$(section 5); s6=$(section 6); s7=$(section 7)

check  "1 observe run completes"                  "$s1" "sandbox destroyed"
check  "1 safe program has no findings"           "$s1" "No suspicious behaviour found."
check_re "2 useful destination is learned"        "$s2" "local_destination|trusted_private_destination"
check  "3 proposal is approved"                   "$s3" "Approved policy"
check_re "4 enforcement allows the workload"      "$s4" "exit: 0"
check  "4 workload really returned data"          "$s4" "item-0"
check  "5 metadata endpoint is blocked"           "$s5" "169.254.169.254:80"
check_blocked "5 metadata endpoint has a BLOCKED line" "$s5" "169\.254\.169\.254:80"
check_blocked "5 shell/network tool has a BLOCKED line" "$s5" "curl"
check_blocked "5 sensitive file has a BLOCKED line"    "$s5" "/etc/shadow"
blocked=$(printf '%s\n' "$s5" | grep -c 'BLOCKED' || true)
if [ "${blocked:-0}" -ge 3 ]; then
  ok "5 at least three blocked actions ($blocked)"
else
  bad "5 expected at least three blocked actions, saw ${blocked:-0}"
fi
check  "6 observing an attack is still a finding" "$s6" "shell_or_network_tool"
check  "7 diff reports a regression"              "$s7" "Behavioural regression detected"

if [ "$fail" -ne 0 ]; then
  echo "verify-demo: FAILED" >&2
  exit 1
fi
echo "verify-demo: PASS"
