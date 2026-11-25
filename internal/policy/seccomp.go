package policy

import (
	"encoding/json"
	"sort"
)

// Syscalls is the seccomp part of a policy (x86_64 syscall numbers).
//
//	Allow: syscalls the workload was seen using in the observe run (from eBPF).
//	       Empty means "no learned allowlist" (e.g. local backend): only the
//	       baseline deny list is applied.
//	Deny:  dangerous syscalls that are refused in every mode.
type Syscalls struct {
	Arch  string   `json:"arch"`
	Allow []int    `json:"allow"`
	Deny  []string `json:"deny"`
}

// BaselineDenySyscalls: kernel-attack-surface syscalls an AI workload never needs.
// Numbers are x86_64 (arch/x86/entry/syscalls/syscall_64.tbl).
var BaselineDenySyscalls = map[int]string{
	101: "ptrace", 155: "pivot_root", 165: "mount", 166: "umount2", 167: "swapon",
	169: "reboot", 175: "init_module", 176: "delete_module", 246: "kexec_load",
	248: "add_key", 250: "keyctl", 272: "unshare", 298: "perf_event_open",
	304: "open_by_handle_at", 308: "setns", 313: "finit_module", 321: "bpf", 323: "userfaultfd",
}

func baselineDenyNames() []string {
	out := make([]string, 0, len(BaselineDenySyscalls))
	for _, n := range BaselineDenySyscalls {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// SeccompProfile renders an OCI/Docker-style seccomp profile, useful for
// review and for reusing the learned policy with runc, crun or Docker.
func (p *Policy) SeccompProfile() ([]byte, error) {
	type rule struct {
		Names  []string `json:"names,omitempty"`
		Nrs    []int    `json:"tracefuse_numbers,omitempty"`
		Action string   `json:"action"`
		Errno  int      `json:"errnoRet,omitempty"`
	}
	prof := struct {
		DefaultAction string   `json:"defaultAction"`
		Architectures []string `json:"architectures"`
		Syscalls      []rule   `json:"syscalls"`
	}{Architectures: []string{"SCMP_ARCH_X86_64"}}
	if len(p.Syscalls.Allow) == 0 {
		prof.DefaultAction = "SCMP_ACT_ALLOW"
	} else {
		prof.DefaultAction = "SCMP_ACT_ERRNO"
		prof.Syscalls = append(prof.Syscalls, rule{Nrs: p.Syscalls.Allow, Action: "SCMP_ACT_ALLOW"})
	}
	prof.Syscalls = append(prof.Syscalls, rule{Names: p.Syscalls.Deny, Action: "SCMP_ACT_ERRNO", Errno: 1})
	return json.MarshalIndent(prof, "", "  ")
}
