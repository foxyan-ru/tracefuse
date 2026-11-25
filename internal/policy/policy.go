// Package policy turns an observed trace into a least-privilege proposal and
// evaluates events against an approved policy.
//
// Security rule: observation never grants permission by itself. Suspicious
// behaviour is reported as a Finding and kept OUT of the proposed allowlist.
package policy

import (
	"fmt"
	"math"
	"net"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tracefuse/tracefuse/internal/trace"
)

type Policy struct {
	ID          string     `json:"id"`
	SourceTrace string     `json:"source_trace"`
	CreatedAt   time.Time  `json:"created_at"`
	Approved    bool       `json:"approved"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	Filesystem  Filesystem `json:"filesystem"`
	Network     Network    `json:"network"`
	Processes   Processes  `json:"processes"`
	Syscalls    Syscalls   `json:"syscalls"`
	Limits      Limits     `json:"limits"`
	Findings    []Finding  `json:"findings,omitempty"`
}

type Filesystem struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
	Deny  []string `json:"deny"`
}

type Network struct {
	Allow []string `json:"allow"`
}

type Processes struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type Limits struct {
	TimeoutSec int `json:"timeout_sec"`
	MemoryMB   int `json:"memory_mb"`
	VCPUs      int `json:"vcpus"`
}

// Finding is something a human should look at before approving.
type Finding struct {
	Severity string `json:"severity"` // low | medium | high | critical
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
}

// Safe baseline: always denied, in every mode, regardless of what was observed.
var (
	BaselineDenyFiles = []string{
		"/etc/shadow", "/etc/sudoers", "/proc/kcore",
		"/root/**", "/home/*/.ssh/**", "/var/run/secrets/**",
	}
	shellLike  = []string{"bash", "curl", "dash", "nc", "ncat", "scp", "sh", "ssh", "wget", "zsh"}
	pkgInstall = map[string]bool{"pip": true, "pip3": true, "npm": true, "apt": true, "apt-get": true, "apk": true}
	metadata   = map[string]bool{"169.254.169.254": true, "fd00:ec2::254": true, "metadata.google.internal": true, "100.100.100.200": true}
)

// ProposeOptions tunes what an observation run is allowed to learn.
type ProposeOptions struct {
	// TrustedDestinations are operator-allowlisted destinations that may be
	// learned even when they resolve to a private range. The Firecracker
	// backend uses this for its TAP gateway (for example 172.16.0.1).
	// Entries are "host" or "host:port"; a bare host matches any port.
	// Cloud metadata and other link-local endpoints are never trusted.
	TrustedDestinations []string
}

// Propose builds a policy from an observe-mode trace with default options.
func Propose(t *trace.Trace) (*Policy, []Finding) {
	return ProposeWith(t, ProposeOptions{})
}

// ProposeWith builds a policy from an observe-mode trace.
func ProposeWith(t *trace.Trace, opts ProposeOptions) (*Policy, []Finding) {
	p := &Policy{SourceTrace: t.ID, CreatedAt: time.Now().UTC()}
	p.Filesystem.Deny = append([]string(nil), BaselineDenyFiles...)
	p.Processes.Deny = append([]string(nil), shellLike...)
	p.Syscalls = Syscalls{Arch: "x86_64", Deny: baselineDenyNames()}
	syscalls := map[int]bool{}
	p.Limits = Limits{
		TimeoutSec: int(math.Max(5, math.Ceil(float64(t.DurationMS)*3/1000))),
		MemoryMB:   256,
		VCPUs:      1,
	}

	read, write, dests, procs := set{}, set{"/tmp/**": true}, set{}, set{}
	var findings []Finding
	seen := set{}
	add := func(sev, kind, format string, a ...any) {
		f := Finding{sev, kind, fmt.Sprintf(format, a...)}
		if key := f.Kind + "|" + f.Detail; !seen[key] {
			seen[key] = true
			findings = append(findings, f)
		}
	}

	for _, e := range t.Events {
		if e.Action == "blocked" {
			add("high", "blocked", "%s by %s (%s): %s", e.Event, e.Process, target(e), e.Reason)
			continue
		}
		switch e.Event {
		case trace.Exec:
			name := ProcName(e)
			switch {
			case contains(shellLike, name):
				add("high", "shell_or_network_tool", "spawned %s (%s)", name, e.Argv)
			case pkgInstall[name]:
				add("medium", "package_install", "ran package manager %s (%s)", name, e.Argv)
			default:
				procs[name] = true
			}
		case trace.FileOpen:
			if MatchAny(BaselineDenyFiles, e.Path) {
				add("critical", "sensitive_file", "%s opened %s", e.Process, e.Path)
				continue
			}
			g := Generalize(e.Path)
			if IsWrite(e) {
				if !strings.HasPrefix(e.Path, "/tmp/") {
					add("medium", "write_outside_tmp", "%s wrote %s", e.Process, e.Path)
				}
				write[g] = true
			} else {
				read[g] = true
			}
		case trace.NetworkConnect, trace.DNS:
			sev, why := ClassifyDestination(e.Destination)
			switch {
			case sev == "critical":
				// Metadata and link-local endpoints are never learnable,
				// even when an operator lists them as trusted.
				add(sev, "sensitive_destination", "%s -> %s: %s (excluded)", e.Process, e.Destination, why)
				continue
			case sev == "high" && trustedDestination(e.Destination, opts.TrustedDestinations):
				add("medium", "trusted_private_destination", "%s -> %s: %s (allowlisted by operator)", e.Process, e.Destination, why)
			case sev == "high":
				add(sev, "sensitive_destination", "%s -> %s: %s (excluded)", e.Process, e.Destination, why)
				continue
			case sev == "low":
				add(sev, "local_destination", "%s -> %s: %s", e.Process, e.Destination, why)
			}
			dests[e.Destination] = true
		case trace.Syscall:
			if name, bad := BaselineDenySyscalls[e.SyscallNr]; bad {
				add("high", "dangerous_syscall", "%s used %s (excluded)", e.Process, name)
				continue
			}
			syscalls[e.SyscallNr] = true
		case trace.PrivChange, trace.Mount:
			add("high", "privileged_operation", "%s attempted %s (%s)", e.Process, e.Event, e.Path)
		}
	}

	p.Filesystem.Read = read.sorted()
	p.Filesystem.Write = write.sorted()
	p.Network.Allow = dests.sorted()
	p.Processes.Allow = procs.sorted()
	for nr := range syscalls {
		p.Syscalls.Allow = append(p.Syscalls.Allow, nr)
	}
	sort.Ints(p.Syscalls.Allow)
	p.Findings = findings
	return p, findings
}

// Evaluate checks one event against an approved policy.
func (p *Policy) Evaluate(e trace.Event) (bool, string) {
	switch e.Event {
	case trace.Exec:
		name := ProcName(e)
		if contains(p.Processes.Deny, name) {
			return false, "process explicitly denied"
		}
		if !contains(p.Processes.Allow, name) {
			return false, "process not in learned policy"
		}
	case trace.FileOpen:
		if MatchAny(p.Filesystem.Deny, e.Path) || MatchAny(BaselineDenyFiles, e.Path) {
			return false, "path denied"
		}
		if IsWrite(e) {
			if !MatchAny(p.Filesystem.Write, e.Path) {
				return false, "write path not in learned policy"
			}
		} else if !MatchAny(p.Filesystem.Read, e.Path) && !MatchAny(p.Filesystem.Write, e.Path) {
			return false, "read path not in learned policy"
		}
	case trace.NetworkConnect, trace.DNS:
		if sev, why := ClassifyDestination(e.Destination); sev == "critical" {
			return false, why
		}
		if !contains(p.Network.Allow, e.Destination) {
			return false, "destination not in learned policy"
		}
	case trace.Syscall:
		if name, bad := BaselineDenySyscalls[e.SyscallNr]; bad {
			return false, "baseline: dangerous syscall " + name
		}
		if len(p.Syscalls.Allow) > 0 && !containsInt(p.Syscalls.Allow, e.SyscallNr) {
			return false, "syscall not in learned policy"
		}
	case trace.PrivChange, trace.Mount:
		return false, "privileged operation not permitted"
	}
	return true, ""
}

// ClassifyDestination flags metadata endpoints and internal networks.
func ClassifyDestination(dest string) (severity, reason string) {
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}
	if metadata[host] {
		return "critical", "cloud metadata endpoint"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", ""
	}
	switch {
	case ip.IsLinkLocalUnicast():
		return "critical", "link-local address (metadata range)"
	case ip.IsLoopback():
		return "low", "loopback (local dev only)"
	case ip.IsPrivate():
		return "high", "private network range"
	}
	return "", ""
}

// trustedDestination reports whether dest matches the operator trust list.
// A bare host entry matches any port; "host:port" matches that port only.
func trustedDestination(dest string, trusted []string) bool {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		host, port = dest, ""
	}
	for _, t := range trusted {
		if t == "" {
			continue
		}
		th, tp, err := net.SplitHostPort(t)
		if err != nil {
			th, tp = t, ""
		}
		if th == host && (tp == "" || tp == port) {
			return true
		}
	}
	return false
}

// Generalize turns a concrete path into a reviewable glob.
//
//	/workspace/main.py                       -> /workspace/**
//	/usr/lib/python3.12/json/decoder.py      -> /usr/lib/python3.12/**
//	/etc/hosts                               -> /etc/hosts (kept exact)
func Generalize(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "/tmp" || strings.HasPrefix(p, "/tmp/") {
		return "/tmp/**"
	}
	if strings.HasPrefix(p, "/workspace/") {
		return "/workspace/**"
	}
	parts := split(p)
	if len(parts) <= 2 {
		return p
	}
	n := 3
	if len(parts)-1 < n {
		n = len(parts) - 1
	}
	return "/" + strings.Join(parts[:n], "/") + "/**"
}

// IsWrite reports whether a file event opened for writing.
func IsWrite(e trace.Event) bool {
	if e.Flags == "w" {
		return true
	}
	if n, err := strconv.Atoi(e.Flags); err == nil {
		const oWRONLY, oRDWR, oCREAT = 0x1, 0x2, 0x40
		return n&(oWRONLY|oRDWR|oCREAT) != 0
	}
	return false
}

// ProcName returns the executable base name for an exec event.
func ProcName(e trace.Event) string {
	if e.Path != "" {
		return filepath.Base(e.Path)
	}
	return e.Process
}

// MatchAny matches a path against globs where "**" spans directories.
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if matchSegs(split(p), split(name)) {
			return true
		}
	}
	return false
}

func matchSegs(p, n []string) bool {
	if len(p) == 0 {
		return len(n) == 0
	}
	if p[0] == "**" {
		for i := 0; i <= len(n); i++ {
			if matchSegs(p[1:], n[i:]) {
				return true
			}
		}
		return false
	}
	if len(n) == 0 {
		return false
	}
	if ok, _ := path.Match(p[0], n[0]); !ok {
		return false
	}
	return matchSegs(p[1:], n[1:])
}

func split(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

func target(e trace.Event) string {
	for _, s := range []string{e.Destination, e.Path, e.Argv} {
		if s != "" {
			return s
		}
	}
	return e.Process
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(sorted []int, v int) bool {
	i := sort.SearchInts(sorted, v)
	return i < len(sorted) && sorted[i] == v
}

type set map[string]bool

func (s set) sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
