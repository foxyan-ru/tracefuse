#!/usr/bin/env bash
# Build guest/out/rootfs.ext4 + guest/out/vmlinux.
# Do not write a distro builder: start from Firecracker's CI images, add our bits.
set -euo pipefail
cd "$(dirname "$0")"
OUT=out; mkdir -p "$OUT"

# 1. Kernel + base rootfs from the Firecracker getting-started guide
#    (https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md).
#    Use a kernel built with CONFIG_DEBUG_INFO_BTF=y and CONFIG_BPF_EVENTS=y for bpftrace.
: "${BASE_ROOTFS:?set BASE_ROOTFS to an ubuntu ext4 image}"
: "${KERNEL:?set KERNEL to a vmlinux with BTF enabled}"
cp "$KERNEL" "$OUT/vmlinux"
cp "$BASE_ROOTFS" "$OUT/rootfs.ext4"
truncate -s 2G "$OUT/rootfs.ext4" && resize2fs "$OUT/rootfs.ext4"

# 2. Install runtime packages + TraceFuse guest files.
MNT=$(mktemp -d)
sudo mount "$OUT/rootfs.ext4" "$MNT"
trap 'sudo umount "$MNT"; rmdir "$MNT"' EXIT
sudo cp /etc/resolv.conf "$MNT/etc/resolv.conf"
sudo chroot "$MNT" sh -c 'apt-get update && apt-get install -y --no-install-recommends python3 python3-seccomp bpftrace nftables iproute2 && apt-get clean'
sudo mkdir -p "$MNT/opt/tracefuse"
sudo cp observer.bt "$MNT/opt/tracefuse/"
sudo cp ../internal/sandbox/tracer.py "$MNT/opt/tracefuse/"
sudo install -m 0755 tracefuse-init "$MNT/sbin/tracefuse-init"
echo "built $OUT/rootfs.ext4 and $OUT/vmlinux"
