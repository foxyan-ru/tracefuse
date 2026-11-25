# Architecture

```
                 CLI (cmd/tracefuse)
                        |
                        v
              controller: store, policy, report, diff
                        |
         +--------------+---------------+
         |                              |
         v                              v
  sandbox.Backend                 policy engine
  (firecracker | local)           Propose / Evaluate / NetworkArtifacts
         |
         v   REST over unix socket: machine-config, boot-source, drives, actions
  Firecracker microVM  -------------------------------------------+
  |  /sbin/tracefuse-init (PID 1)                                 |
  |    nftables allowlist (enforce)                               |
  |    cgroup "workload": memory.max, pids.max                    |
  |    bpftrace observer.bt  --> exec/open/connect/priv/mount     |
  |    python3 tracer.py main.py  --> policy agent decisions      |
  +--- ttyS0: TFEVT / TFOUT / TFEXIT / TFBLOCK lines -------------+
         |
         v
  trace JSON (.tracefuse/traces) -> report, proposal, diff
```

Trust boundary: the controller is outside the VM and treats every console line
as untrusted. The sandbox ID on every event is set by the controller.

Two independent guest signals: eBPF (kernel view) and the audit-hook agent
(interpreter view). `report.CrossCheck` flags anything eBPF saw that the
approved policy does not allow - i.e. something got past in-guest enforcement.
