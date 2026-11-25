# Threat model (MVP)

| Threat | Mitigation | Status |
|---|---|---|
| Workload escapes to host kernel | Firecracker/KVM boundary, minimal devices | firecracker backend |
| Reaches cloud metadata | baseline deny in agent + nftables drop 169.254.0.0/16 | done |
| Exfiltrates to arbitrary host | nftables `policy drop`, allowlist of approved IP:port | done |
| Poisons learning (does bad thing in observe run) | findings excluded from proposal; human approval required | done |
| Reaches a LAN or host service over a private range | private destinations excluded unless the operator lists an exact host:port (`--trusted-hosts`, e.g. the TAP gateway); metadata and link-local never learnable | done |
| Disables in-guest agent | nftables still enforces network; eBPF cross-check reports | partial |
| Forges events on the console | controller parses defensively, owns sandbox IDs; signing is TODO | partial |
| Kernel exploit inside guest disables eBPF | out of scope: guest kernel is untrusted by design; isolation still holds | accepted |
| Resource exhaustion | timeout kill, VM memory size, cgroup memory/pids | done |
| Syscall attack surface | baseline deny (ptrace, bpf, mount, kexec...) always; learned allowlist from eBPF in enforce (default EPERM) | done (x86_64) |
| Missing seccomp support in guest | `TF_REQUIRE_SECCOMP=1` makes the run fail closed (exit 126) | done |

Local backend: none of the above holds. It is a developer tool.
