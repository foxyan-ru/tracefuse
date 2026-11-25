"""TraceFuse workload tracer and in-guest policy agent.

Runs the workload under a Python audit hook (PEP 578).

* Inside the Firecracker guest it is the policy agent: guest eBPF is the
  independent source of truth for observation, nftables is the kernel-level
  network gate, and this hook gives attributable, early decisions for
  process, file and network actions.
* In the local dev backend it is the only observer. That backend is NOT a
  security boundary; it exists so the policy loop can be developed on a laptop.
"""
import fnmatch
import json
import os
import runpy
import sys
import time
import errno
import traceback  # pre-imported: must not be loaded after the hook is active

MODE = os.environ.get("TF_MODE", "observe")
SANDBOX = os.environ.get("TF_SANDBOX_ID", "")

def _roots(env, default):
    p = os.environ.get(env, default)
    return {os.path.abspath(p), os.path.realpath(p)}

WORKSPACES = _roots("TF_WORKSPACE", os.getcwd())
TMPS = _roots("TF_TMP", "/tmp")
_out = open(os.environ.get("TF_EVENTS", "/dev/stderr"), "a", buffering=1)

_policy = None
_pp = os.environ.get("TF_POLICY")
if _pp and os.path.exists(_pp):
    with open(_pp) as fh:
        _policy = json.load(fh)

BASELINE_DENY_FILES = ["/etc/shadow", "/etc/sudoers", "/proc/kcore", "/root/**",
                       "/home/*/.ssh/**", "/var/run/secrets/**"]
METADATA = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "100.100.100.200"}

_busy = False


def _segs(s):
    s = s.strip("/")
    return s.split("/") if s else []


def _m(p, n):
    if not p:
        return not n
    if p[0] == "**":
        return any(_m(p[1:], n[i:]) for i in range(len(n) + 1))
    return bool(n) and fnmatch.fnmatchcase(n[0], p[0]) and _m(p[1:], n[1:])


def match_any(patterns, path):
    return any(_m(_segs(p), _segs(path)) for p in (patterns or []))


def vpath(p):
    """Map real host paths to stable virtual ones so policies are portable."""
    try:
        if isinstance(p, int):
            return None
        p = os.path.abspath(os.fsdecode(p))
    except Exception:
        return None
    for roots, virt in ((WORKSPACES, "/workspace"), (TMPS, "/tmp")):
        for real in roots:
            if p == real or p.startswith(real + os.sep):
                return virt + p[len(real):]
    return p


def emit(event, process=None, **kw):
    now = time.time()
    rec = {
        "sandbox_id": SANDBOX,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % (int(now * 1000) % 1000),
        "event": event,
        "process": process or os.path.basename(sys.executable),
        "pid": os.getpid(),
        "source": "audit",
        "action": "observed",
    }
    rec.update({k: v for k, v in kw.items() if v is not None})
    _out.write(json.dumps(rec) + "\n")


def _host(dest):
    return dest.rsplit(":", 1)[0].strip("[]")


def decide(event, kw):
    """Return (allowed, reason). The baseline applies in every mode."""
    if event == "file_open" and match_any(BASELINE_DENY_FILES, kw["path"]):
        return False, "baseline: sensitive file"
    if event in ("network_connect", "dns"):
        h = _host(kw["destination"])
        if h in METADATA or h.startswith("169.254."):
            return False, "baseline: cloud metadata endpoint"
    if MODE != "enforce" or _policy is None:
        return True, None

    fs = _policy.get("filesystem") or {}
    allow_net = (_policy.get("network") or {}).get("allow") or []
    procs = _policy.get("processes") or {}
    if event == "exec":
        name = kw["process"]
        if name in (procs.get("deny") or []):
            return False, "process explicitly denied"
        if name not in (procs.get("allow") or []):
            return False, "process not in learned policy"
    elif event == "file_open":
        p = kw["path"]
        if match_any(fs.get("deny"), p):
            return False, "path denied by policy"
        if kw.get("flags") == "w":
            if not match_any(fs.get("write"), p):
                return False, "write path not in learned policy"
        elif not (match_any(fs.get("read"), p) or match_any(fs.get("write"), p)):
            return False, "read path not in learned policy"
    elif event in ("dns", "network_connect"):
        if kw["destination"] not in allow_net:
            return False, "destination not in learned policy"
    return True, None


def _translate(name, args):
    if name == "open":
        path = vpath(args[0])
        if path is None:
            return None
        mode, flags = str(args[1] or "r"), args[2] or 0
        write = any(c in mode for c in "wax+") or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        return "file_open", {"path": path, "flags": "w" if write else "r"}
    if name == "socket.getaddrinfo":
        host = args[0]
        if host is None:
            return None
        return "dns", {"destination": "%s:%s" % (os.fsdecode(host), args[1])}
    if name == "socket.connect":
        addr = args[1]
        if isinstance(addr, tuple) and len(addr) >= 2:
            return "network_connect", {"destination": "%s:%s" % (addr[0], addr[1])}
        return None
    if name == "subprocess.Popen":
        exe, argv = args[0], args[1]
        prog = os.fsdecode(exe) if exe is not None else str(argv)
        shown = " ".join(map(os.fsdecode, argv)) if isinstance(argv, (list, tuple)) else str(argv)
        return "exec", {"process": os.path.basename(prog), "path": prog, "argv": shown}
    if name in ("os.exec", "os.posix_spawn"):
        prog = os.fsdecode(args[0])
        return "exec", {"process": os.path.basename(prog), "path": prog}
    if name == "os.system":
        return "exec", {"process": "sh", "path": "/bin/sh", "argv": os.fsdecode(args[0])}
    return None


def hook(name, args):
    global _busy
    if _busy:
        return
    _busy = True
    try:
        ev = _translate(name, args)
        if ev is None:
            return
        event, kw = ev
        ok, reason = decide(event, kw)
        if ok:
            emit(event, **kw)
            return
        emit(event, action="blocked", reason=reason, **kw)
        what = kw.get("destination") or kw.get("path")
        raise PermissionError("TraceFuse blocked %s %s: %s" % (event, what, reason))
    finally:
        _busy = False


# Minimal allowlist for a clean interpreter shutdown. These are needed after
# the workload returns, when no further learning is possible.
ALWAYS_ALLOW = ["exit", "exit_group", "rt_sigreturn", "rt_sigprocmask",
                "write", "close", "futex", "munmap", "clock_gettime", "getpid"]

# Benign runtime syscalls Python can reach on paths the observe run may not
# have taken (signals, timers, memory growth). They do not bypass the
# action-level policy: the audit hook still decides files/processes. Network
# syscalls are deliberately absent: they must be learned, and nftables is the
# backstop. TF_SECCOMP_STRICT=1 removes this set.
RUNTIME_ALLOW = [
    "read", "mmap", "mprotect", "madvise", "brk", "mremap",
    "newfstatat", "fstat", "statx", "lseek", "fcntl", "ioctl", "getdents64",
    "rt_sigaction", "sigaltstack", "tgkill", "gettid", "getuid", "geteuid",
    "getgid", "getegid", "getcwd", "readlink", "readlinkat", "access", "faccessat",
    "getrandom", "clock_nanosleep", "nanosleep",
    "poll", "ppoll", "select", "pselect6", "epoll_create1", "epoll_ctl", "epoll_wait",
    "pipe2", "dup", "dup2", "wait4", "prlimit64", "arch_prctl",
    "set_tid_address", "set_robust_list", "rseq",
    "sched_getaffinity", "sched_yield", "uname", "sysinfo",
]


def apply_seccomp():
    """Kernel-level syscall filter (libseccomp; python3-seccomp in the guest).

    observe: default ALLOW, baseline dangerous syscalls -> EPERM.
    enforce: default EPERM, only learned + ALWAYS_ALLOW + RUNTIME_ALLOW pass.
    Applied after imports and before the workload runs; it can never be lifted
    (libseccomp sets no_new_privs).
    """
    sc = (_policy or {}).get("syscalls") or {}
    deny = sc.get("deny") or []
    allow = [int(n) for n in (sc.get("allow") or [])]
    required = os.environ.get("TF_REQUIRE_SECCOMP") == "1"
    strict = os.environ.get("TF_SECCOMP_STRICT") == "1"

    # In the guest, an enforce run without learned syscalls would silently
    # fall back to a permissive filter. Refuse instead.
    if MODE == "enforce" and required and not allow:
        print("TraceFuse: enforce mode has no learned syscalls; refusing to run", file=sys.stderr)
        sys.exit(126)

    try:
        import seccomp
    except ImportError:
        if required:
            print("TraceFuse: seccomp required but python3-seccomp is missing", file=sys.stderr)
            sys.exit(126)
        print("TraceFuse: seccomp unavailable here, skipping (dev backend)", file=sys.stderr)
        return

    try:
        if MODE == "enforce" and allow:
            f = seccomp.SyscallFilter(defaction=seccomp.ERRNO(errno.EPERM))
            for nr in allow:
                try:
                    f.add_rule(seccomp.ALLOW, nr)
                except Exception:
                    pass
            extra = ALWAYS_ALLOW if strict else ALWAYS_ALLOW + RUNTIME_ALLOW
            for name in extra:
                try:
                    f.add_rule(seccomp.ALLOW, name)
                except Exception:
                    pass
        else:
            f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
            for name in deny or ["ptrace", "mount", "bpf", "kexec_load", "init_module", "finit_module", "unshare", "setns"]:
                try:
                    f.add_rule(seccomp.ERRNO(errno.EPERM), name)
                except Exception:
                    pass
        f.load()
    except Exception as e:
        if required:
            print("TraceFuse: seccomp setup failed: %s" % e, file=sys.stderr)
            sys.exit(126)
        print("TraceFuse: seccomp unavailable here, skipping (dev backend): %s" % e, file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("usage: tracer.py <script>", file=sys.stderr)
        return 2
    if MODE == "enforce" and _policy is None:
        print("TraceFuse: enforce mode without a policy; refusing to run", file=sys.stderr)
        return 126
    script = os.path.abspath(sys.argv[1])
    mem = os.environ.get("TF_MEMORY_MB")
    if mem and sys.platform.startswith("linux"):
        import resource
        limit = int(mem) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    emit("exec", path=sys.executable)
    sys.argv = [script]
    if sys.platform.startswith("linux"):
        apply_seccomp()
    sys.addaudithook(hook)  # cannot be removed once installed
    rc = 0
    try:
        runpy.run_path(script, run_name="__main__")
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:
        traceback.print_exc()
        rc = 1
    emit("process_exit", exit_code=rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
