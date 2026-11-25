package policy

import (
	"testing"

	"github.com/tracefuse/tracefuse/internal/trace"
)

func ev(kind, proc, p, dest, flags string) trace.Event {
	return trace.Event{Event: kind, Process: proc, Path: p, Destination: dest, Flags: flags, Action: "observed"}
}

func TestProposeExcludesSuspiciousBehaviour(t *testing.T) {
	tr := &trace.Trace{ID: "trace-test", DurationMS: 400, Events: []trace.Event{
		ev(trace.Exec, "python3", "/usr/bin/python3", "", ""),
		ev(trace.FileOpen, "python3", "/workspace/main.py", "", "r"),
		ev(trace.FileOpen, "python3", "/usr/lib/python3.12/json/decoder.py", "", "r"),
		ev(trace.NetworkConnect, "python3", "", "93.184.216.34:443", ""),
		ev(trace.NetworkConnect, "python3", "", "169.254.169.254:80", ""),
		ev(trace.Exec, "python3", "/usr/bin/curl", "", ""),
		ev(trace.FileOpen, "python3", "/etc/shadow", "", "r"),
	}}
	p, findings := Propose(tr)

	if contains(p.Network.Allow, "169.254.169.254:80") {
		t.Fatal("metadata endpoint must never be learned")
	}
	if !contains(p.Network.Allow, "93.184.216.34:443") {
		t.Fatal("expected public destination in proposal")
	}
	if contains(p.Processes.Allow, "curl") {
		t.Fatal("curl must not be auto-allowed")
	}
	if !contains(p.Filesystem.Read, "/usr/lib/python3.12/**") || !contains(p.Filesystem.Read, "/workspace/**") {
		t.Fatalf("unexpected read paths: %v", p.Filesystem.Read)
	}
	if len(findings) < 3 {
		t.Fatalf("expected findings for metadata, curl and shadow, got %v", findings)
	}
}

func TestEvaluate(t *testing.T) {
	p := &Policy{
		Filesystem: Filesystem{Read: []string{"/workspace/**"}, Write: []string{"/tmp/**"}, Deny: BaselineDenyFiles},
		Network:    Network{Allow: []string{"127.0.0.1:8080"}},
		Processes:  Processes{Allow: []string{"python3"}, Deny: []string{"curl"}},
	}
	cases := []struct {
		e    trace.Event
		want bool
	}{
		{ev(trace.NetworkConnect, "python3", "", "127.0.0.1:8080", ""), true},
		{ev(trace.NetworkConnect, "python3", "", "169.254.169.254:80", ""), false},
		{ev(trace.NetworkConnect, "python3", "", "10.0.0.5:5432", ""), false},
		{ev(trace.Exec, "python3", "/usr/bin/curl", "", ""), false},
		{ev(trace.FileOpen, "python3", "/workspace/data.csv", "", "r"), true},
		{ev(trace.FileOpen, "python3", "/workspace/data.csv", "", "w"), false},
		{ev(trace.FileOpen, "python3", "/tmp/out.json", "", "w"), true},
		{ev(trace.FileOpen, "python3", "/etc/shadow", "", "r"), false},
	}
	for _, c := range cases {
		if got, why := p.Evaluate(c.e); got != c.want {
			t.Errorf("%s %s%s: got %v (%s), want %v", c.e.Event, c.e.Path, c.e.Destination, got, why, c.want)
		}
	}
}

func TestMatchAny(t *testing.T) {
	if !MatchAny([]string{"/home/*/.ssh/**"}, "/home/dev/.ssh/id_rsa") {
		t.Fatal("expected ssh key match")
	}
	if MatchAny([]string{"/workspace/**"}, "/workspacex/a") {
		t.Fatal("prefix must respect segment boundaries")
	}
	if !MatchAny([]string{"/tmp/**"}, "/tmp") {
		t.Fatal("** should match zero segments")
	}
}
