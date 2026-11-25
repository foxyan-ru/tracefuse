#!/usr/bin/env bash
# End-to-end demo: observe -> approve -> enforce -> attack blocked -> diff.
# Default backend is "local" so it runs on any laptop. On a KVM host:
#   TF_BACKEND=firecracker TF_TAP=tf0 ./scripts/demo.sh
# The real backend has no DHCP or DNS in the guest, so the mock API listens on
# the TAP gateway (172.16.0.1). That private address must be operator-trusted
# or the proposal deliberately refuses to learn it.
set -euo pipefail
cd "$(dirname "$0")/.."
TF=./bin/tracefuse
export TRACEFUSE_STATE=${TRACEFUSE_STATE:-.tracefuse}

MOCK_HOST=${TF_MOCK_HOST:-127.0.0.1}
if [ "${TF_BACKEND:-local}" = "firecracker" ]; then
  MOCK_HOST=${TF_MOCK_HOST:-172.16.0.1}
  export TF_MOCK_HOST="$MOCK_HOST"
  export TF_TRUSTED_HOSTS=${TF_TRUSTED_HOSTS:-$MOCK_HOST}
fi

last() { cat "$TRACEFUSE_STATE/last_trace"; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

python3 demos/mock_server.py "$MOCK_HOST" & MOCK=$!
trap 'kill $MOCK 2>/dev/null' EXIT
sleep 0.5

step "1. Safe program (observe)"
$TF run --code demos/safe.py --mode observe

step "2. Useful program (observe) - learns $MOCK_HOST:8080"
$TF run --code demos/useful.py --mode observe
USEFUL=$(last)

step "3. Human approves the proposal"
$TF policy approve "$USEFUL" | tail -n 1

step "4. Useful program (enforce) - succeeds"
$TF run --code demos/useful.py --mode enforce --policy "$USEFUL"

step "5. Malicious variant under the SAME policy - blocked"
$TF run --code demos/malicious.py --mode enforce --policy "$USEFUL" || true

step "6. Malicious variant (observe) - learning does not grant trust"
$TF run --code demos/malicious.py --mode observe
MAL=$(last)

step "7. Behavioural diff"
$TF diff "$USEFUL" "$MAL"
