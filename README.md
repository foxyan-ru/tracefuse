# TraceFuse

An adaptive Firecracker sandbox for AI-generated workloads.

> Observe the first execution, convert behaviour into a least-privilege policy,
> require approval, then replay the workload under that policy.

## Quick start (any laptop, ~1 minute)

```bash
make test        # unit tests: policy proposal, evaluation, diff, console protocol
make demo        # observe -> approve -> enforce -> attack blocked -> diff
```

The demo uses the **local** backend so you can work on the policy loop without
KVM. The local backend shares your kernel and is **not a security boundary**.

## Real isolation (Linux + KVM)

```bash
# 1. kernel with BTF + base rootfs (see guest/build-rootfs.sh header)
BASE_ROOTFS=ubuntu.ext4 KERNEL=vmlinux make guest
# 2. host TAP device, no NAT
./scripts/setup-tap.sh tf0
# 3. mock API on the TAP address, then point demos/useful.py at 172.16.0.1
python3 demos/mock_server.py 172.16.0.1 &
TF_BACKEND=firecracker TF_TAP=tf0 make demo
```

## Commands

| Command | What it does |
|---|---|
| `tracefuse run --code f.py --mode observe` | run once, record trace, propose policy (unapproved) |
| `tracefuse policy show ID` / `approve ID` | review / approve a proposal |
| `tracefuse run --code f.py --mode enforce --policy ID` | run under an approved policy, fail closed |
| `tracefuse diff A B` | behavioural regression between two traces |
| `tracefuse report ID` | full JSON trace (the "security receipt") |

## Layout

```
cmd/tracefuse/          CLI
internal/firecracker/   microVM lifecycle over the Firecracker REST API (+ snapshots)
internal/sandbox/       backends: firecracker (real) and local (dev); tracer.py policy agent
internal/policy/        propose / evaluate / nftables rendering, safe baseline
internal/diff/          behavioural diffing
internal/trace/         event schema
internal/report/        timelines, findings, cross-checks
guest/                  init (PID 1), bpftrace observer, rootfs build
demos/                  safe, useful, malicious programs + mock API
docs/                   architecture and threat model
```

## Security rules this code enforces

1. Observation never grants permission. Findings (metadata IPs, private ranges,
   shells, sensitive files, privilege changes) are excluded from proposals.
2. Enforce mode refuses unapproved policies.
3. Baseline deny applies in every mode (metadata endpoints, `/etc/shadow`, ...).
4. Network enforcement in the guest fails closed (nftables `policy drop`).
5. Host eBPF does not see guest processes; observation lives in the guest and
   the controller treats everything from the guest as untrusted input.
6. seccomp: dangerous syscalls (ptrace, bpf, mount, kexec, module loading,
   unshare/setns...) are refused in every mode; in enforce mode only syscalls
   eBPF saw during the approved observe run are allowed (default EPERM).
   An OCI-style `seccomp.json` is generated with every enforced run.

## Not yet (roadmap weeks 6-8)

arm64 syscall tables, snapshot-restore fast path in the CLI, vsock channel
instead of serial, signed trace receipts, IPv6, a web UI. See `docs/`.

## Sources

Firecracker design doc, Firecracker announcement, Fly.io sandboxing posts,
Modal sandbox posts, Datadog eBPF hardening lessons, CubeSandbox networking.
