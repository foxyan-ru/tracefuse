#!/usr/bin/env bash
# Read-only preflight for the Firecracker backend (Stage 2).
# It never creates, changes or deletes a resource.
#
# Usage: ./scripts/check-host.sh [--help]
# Env:   TF_FIRECRACKER, TF_KERNEL, TF_ROOTFS, TF_TAP, TF_MOCK_URL
set -uo pipefail

case "${1:-}" in
  -h|--help)
    sed -n '2,8p' "$0"
    exit 0
    ;;
esac

FC=${TF_FIRECRACKER:-firecracker}
KERNEL=${TF_KERNEL:-guest/out/vmlinux}
ROOTFS=${TF_ROOTFS:-guest/out/rootfs.ext4}
TAP=${TF_TAP:-tf0}
MOCK_URL=${TF_MOCK_URL:-http://172.16.0.1:8080/data}

fail=0
ok() { printf 'ok   %s\n' "$*"; }
warn() { printf 'warn %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(uname -s)" = "Linux" ] || { bad "host is not Linux ($(uname -s)); Firecracker needs Linux/KVM"; exit 1; }

# KVM: the microVM cannot start without it.
if [ -c /dev/kvm ]; then
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ok "/dev/kvm is present and accessible"
  else
    bad "/dev/kvm exists but is not readable/writable by $USER (add the user to the kvm group)"
  fi
else
  bad "/dev/kvm is missing (enable virtualization in the hypervisor)"
fi

if grep -Eq '(^flags|^Features)[[:space:]]*:.*[[:space:]](vmx|svm)([[:space:]]|$)' /proc/cpuinfo; then
  ok "CPU exposes hardware virtualization (vmx/svm)"
else
  warn "CPU flags do not expose vmx/svm; nested virtualization may be disabled"
fi

if have "$FC"; then
  ok "$("$FC" --version 2>&1 | head -n1)"
else
  bad "firecracker binary not found: $FC (set TF_FIRECRACKER)"
fi

# Guest kernel: ELF vmlinux with BTF for bpftrace.
if [ -f "$KERNEL" ]; then
  if have file && file -b "$KERNEL" | grep -q 'ELF'; then
    ok "kernel is an ELF vmlinux: $KERNEL"
  else
    bad "kernel is not an ELF vmlinux: $KERNEL"
  fi
  if have readelf; then
    if readelf -S "$KERNEL" 2>/dev/null | grep -q '\.BTF'; then
      ok "kernel has a .BTF section"
    else
      bad "kernel has no .BTF section (bpftrace needs CONFIG_DEBUG_INFO_BTF=y)"
    fi
  else
    warn "readelf not installed; cannot verify the kernel .BTF section"
  fi
else
  bad "guest kernel missing: $KERNEL (run: BASE_ROOTFS=... KERNEL=... make guest)"
fi

# Guest rootfs: an ext4 image with the TraceFuse init installed.
if [ -f "$ROOTFS" ]; then
  if have blkid; then
    fstype=$(blkid -p -o value -s TYPE "$ROOTFS" 2>/dev/null || true)
    if [ "$fstype" = "ext4" ]; then
      ok "rootfs is ext4: $ROOTFS"
    else
      bad "rootfs is not ext4 (detected: ${fstype:-unknown}): $ROOTFS"
    fi
  elif have file && file -b "$ROOTFS" | grep -q 'ext4'; then
    ok "rootfs looks like ext4: $ROOTFS"
  else
    warn "cannot verify the rootfs filesystem type (install e2fsprogs)"
  fi
else
  bad "guest rootfs missing: $ROOTFS (run: BASE_ROOTFS=... KERNEL=... make guest)"
fi

for tool in mkfs.ext4 truncate resize2fs sudo ip; do
  have "$tool" && ok "host tool: $tool" || bad "host tool missing: $tool"
done

# TAP device: guest networking is host-only by design (no NAT).
if have ip; then
  if ip link show "$TAP" >/dev/null 2>&1; then
    if ip -4 -o addr show dev "$TAP" 2>/dev/null | grep -q '172\.16\.0\.1/30'; then
      ok "TAP $TAP has 172.16.0.1/30"
    else
      bad "TAP $TAP is missing 172.16.0.1/30 (run: sudo ./scripts/setup-tap.sh $TAP)"
    fi
    if ip -o link show dev "$TAP" 2>/dev/null | grep -q 'UP'; then
      ok "TAP $TAP is up"
    else
      bad "TAP $TAP is down (run: sudo ip link set $TAP up)"
    fi
  else
    bad "TAP $TAP does not exist (run: sudo ./scripts/setup-tap.sh $TAP)"
  fi
fi

if have curl; then
  if curl -fsS -m 2 "$MOCK_URL" >/dev/null 2>&1; then
    ok "mock API answers at $MOCK_URL"
  else
    warn "mock API not answering at $MOCK_URL (start: python3 demos/mock_server.py 172.16.0.1)"
  fi
else
  warn "curl not installed; cannot probe the mock API"
fi

if [ "$fail" -ne 0 ]; then
  echo "check-host: FAILED (fix the FAIL lines above)" >&2
  exit 1
fi
echo "check-host: PASS"
echo "next: TF_BACKEND=firecracker TF_TAP=$TAP make demo"
