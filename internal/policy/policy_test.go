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

func TestProposeTrustedPrivateDestination(t *testing.T) {
	tr := &trace.Trace{ID: "trace-tap", DurationMS: 200, Events: []trace.Event{
		ev(trace.Exec, "python3", "/usr/bin/python3", "", ""),
		ev(trace.NetworkConnect, "python3", "", "172.16.0.1:8080", ""),
		ev(trace.NetworkConnect, "python3", "", "169.254.169.254:80", ""),
	}}

	// Default: a private TAP gateway is not learned.
	p, findings := Propose(tr)
	if contains(p.Network.Allow, "172.16.0.1:8080") {
		t.Fatal("private destination must not be learned without operator trust")
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding for the excluded private destination")
	}

	// Operator trust: the exact TAP gateway is learned with a visible finding,
	// but metadata stays excluded no matter what is trusted.
	p, findings = ProposeWith(tr, ProposeOptions{TrustedDestinations: []string{"172.16.0.1"}})
	if !contains(p.Network.Allow, "172.16.0.1:8080") {
		t.Fatalf("trusted TAP destination missing from proposal: %v", p.Network.Allow)
	}
	if contains(p.Network.Allow, "169.254.169.254:80") {
		t.Fatal("metadata endpoint must never be learned, even when trusted")
	}
	trusted := false
	for _, f := range findings {
		if f.Kind == "trusted_private_destination" {
			trusted = true
		}
	}
	if !trusted {
		t.Fatalf("expected a trusted_private_destination finding, got %v", findings)
	}

	// Port scoping: trusting the host for another port does not open 8080.
	p, _ = ProposeWith(tr, ProposeOptions{TrustedDestinations: []string{"172.16.0.1:9090"}})
	if contains(p.Network.Allow, "172.16.0.1:8080") {
		t.Fatal("trust entry for a different port must not match")
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
