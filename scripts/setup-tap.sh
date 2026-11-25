#!/usr/bin/env bash
# Host side of guest networking. No NAT: the guest can only reach the host
# (e.g. the mock API on 172.16.0.1:8080). Add NAT deliberately, never by default.
set -euo pipefail
TAP=${1:-tf0}
sudo ip tuntap add dev "$TAP" mode tap
sudo ip addr add 172.16.0.1/30 dev "$TAP"
sudo ip link set "$TAP" up
echo "export TF_TAP=$TAP"
