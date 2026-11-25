// Package diff compares the kernel-level behavioural footprint of two runs.
// Two programs can print the same output and still behave very differently.
package diff

import (
	"fmt"
	"io"
	"sort"

	"github.com/tracefuse/tracefuse/internal/policy"
	"github.com/tracefuse/tracefuse/internal/trace"
)

type Footprint struct {
	FilesRead    map[string]bool
	Destinations map[string]bool
	Processes    map[string]bool
	Blocked      int
	DurationMS   int64
}

func FootprintOf(t *trace.Trace) Footprint {
	f := Footprint{FilesRead: map[string]bool{}, Destinations: map[string]bool{}, Processes: map[string]bool{}, DurationMS: t.DurationMS}
	for _, e := range t.Events {
		if e.Action == "blocked" {
			f.Blocked++
		}
		switch e.Event {
		case trace.FileOpen:
			if !policy.IsWrite(e) {
				f.FilesRead[e.Path] = true
			}
		case trace.NetworkConnect:
			f.Destinations[e.Destination] = true
		case trace.Exec:
			f.Processes[policy.ProcName(e)] = true
		}
	}
	return f
}

type Result struct {
	A, B                     *trace.Trace
	FA, FB                   Footprint
	AddedFiles, RemovedFiles []string
	AddedDests, RemovedDests []string
	AddedProcs, RemovedProcs []string
	BlockedDelta             int
}

// Regression is true when B can do something A could not.
func (r Result) Regression() bool {
	return len(r.AddedDests) > 0 || len(r.AddedProcs) > 0 || r.BlockedDelta > 0 || len(r.AddedFiles) > 0
}

func Compare(a, b *trace.Trace) Result {
	fa, fb := FootprintOf(a), FootprintOf(b)
	r := Result{A: a, B: b, FA: fa, FB: fb, BlockedDelta: fb.Blocked - fa.Blocked}
	r.AddedFiles, r.RemovedFiles = delta(fa.FilesRead, fb.FilesRead)
	r.AddedDests, r.RemovedDests = delta(fa.Destinations, fb.Destinations)
	r.AddedProcs, r.RemovedProcs = delta(fa.Processes, fb.Processes)
	return r
}

func (r Result) Write(w io.Writer) {
	row := func(name string, f Footprint, t *trace.Trace) {
		fmt.Fprintf(w, "%s (%s):\n  - %d files read\n  - %d network destinations\n  - %d processes\n  - %d blocked actions\n  - %d ms\n",
			name, t.ID, len(f.FilesRead), len(f.Destinations), len(f.Processes), f.Blocked, f.DurationMS)
	}
	row("Version A", r.FA, r.A)
	row("Version B", r.FB, r.B)
	if !r.Regression() {
		fmt.Fprintln(w, "\nNo behavioural regression.")
		return
	}
	fmt.Fprintln(w, "\nBehavioural regression detected:")
	fmt.Fprintf(w, "  %+d file reads\n  %+d network destinations\n  %+d processes\n  %+d blocked actions\n",
		len(r.AddedFiles)-len(r.RemovedFiles), len(r.AddedDests)-len(r.RemovedDests),
		len(r.AddedProcs)-len(r.RemovedProcs), r.BlockedDelta)
	list := func(label string, items []string) {
		for _, s := range items {
			fmt.Fprintf(w, "  + %s %s\n", label, s)
		}
	}
	list("destination", r.AddedDests)
	list("process", r.AddedProcs)
	if len(r.AddedFiles) <= 15 {
		list("file", r.AddedFiles)
	}
}

func delta(a, b map[string]bool) (added, removed []string) {
	for k := range b {
		if !a[k] {
			added = append(added, k)
		}
	}
	for k := range a {
		if !b[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}
