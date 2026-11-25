package diff

import (
	"testing"

	"github.com/tracefuse/tracefuse/internal/trace"
)

func TestCompareDetectsNewShellAndDestination(t *testing.T) {
	a := &trace.Trace{ID: "a", Events: []trace.Event{
		{Event: trace.NetworkConnect, Destination: "127.0.0.1:8080", Action: "observed"},
	}}
	b := &trace.Trace{ID: "b", Events: []trace.Event{
		{Event: trace.NetworkConnect, Destination: "127.0.0.1:8080", Action: "observed"},
		{Event: trace.NetworkConnect, Destination: "169.254.169.254:80", Action: "blocked"},
		{Event: trace.Exec, Path: "/bin/bash", Action: "observed"},
	}}
	r := Compare(a, b)
	if !r.Regression() || len(r.AddedDests) != 1 || len(r.AddedProcs) != 1 || r.BlockedDelta != 1 {
		t.Fatalf("unexpected diff: %+v", r)
	}
}
