package policy

import (
	"encoding/json"
	"testing"

	"github.com/tracefuse/tracefuse/internal/trace"
)

func TestSyscallLearningExcludesDangerous(t *testing.T) {
	tr := &trace.Trace{ID: "trace-sc", DurationMS: 100, Events: []trace.Event{
		{Event: trace.Syscall, Process: "python3", SyscallNr: 0, Action: "observed"},   // read
		{Event: trace.Syscall, Process: "python3", SyscallNr: 257, Action: "observed"}, // openat
		{Event: trace.Syscall, Process: "python3", SyscallNr: 101, Action: "observed"}, // ptrace
	}}
	p, findings := Propose(tr)
	if len(p.Syscalls.Allow) != 2 || p.Syscalls.Allow[0] != 0 || p.Syscalls.Allow[1] != 257 {
		t.Fatalf("allow = %v", p.Syscalls.Allow)
	}
	if len(findings) != 1 || findings[0].Kind != "dangerous_syscall" {
		t.Fatalf("findings = %v", findings)
	}
	if ok, _ := p.Evaluate(trace.Event{Event: trace.Syscall, SyscallNr: 257}); !ok {
		t.Fatal("learned syscall should be allowed")
	}
	if ok, _ := p.Evaluate(trace.Event{Event: trace.Syscall, SyscallNr: 42}); ok {
		t.Fatal("unlearned syscall should be denied")
	}
	if ok, _ := p.Evaluate(trace.Event{Event: trace.Syscall, SyscallNr: 321}); ok {
		t.Fatal("bpf must always be denied")
	}
	b, err := p.SeccompProfile()
	if err != nil {
		t.Fatal(err)
	}
	var prof map[string]any
	if err := json.Unmarshal(b, &prof); err != nil || prof["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Fatalf("profile: %s", b)
	}
}
