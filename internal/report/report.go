// Package report renders human-readable run reports.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/tracefuse/tracefuse/internal/policy"
	"github.com/tracefuse/tracefuse/internal/trace"
)

// PrintRun prints a timeline of notable events. Interpreter/library file
// reads are summarised rather than listed.
func PrintRun(w io.Writer, t *trace.Trace) {
	fmt.Fprintf(w, "trace:    %s\nsandbox:  %s (%s backend, %s mode)\nduration: %d ms   exit: %d   timed_out: %v\n",
		t.ID, t.SandboxID, t.Backend, t.Mode, t.DurationMS, t.ExitCode, t.TimedOut)
	if t.Stdout != "" {
		fmt.Fprintf(w, "\n--- stdout ---\n%s", indentEnd(t.Stdout))
	}
	fmt.Fprintln(w, "\n--- timeline ---")
	libReads, syscalls := 0, 0
	for _, e := range t.Events {
		if e.Event == trace.Syscall && e.Action != "blocked" {
			syscalls++
			continue
		}
		if e.Event == trace.FileOpen && e.Action != "blocked" &&
			!strings.HasPrefix(e.Path, "/workspace/") && !policy.IsWrite(e) {
			libReads++
			continue
		}
		ts := e.Timestamp.Format("15:04:05.000")
		tag := " "
		if e.Action == "blocked" {
			tag = "BLOCKED"
		}
		fmt.Fprintf(w, "%s %-7s %-15s %-12s %s", ts, tag, e.Event, e.Process, describe(e))
		if e.Reason != "" {
			fmt.Fprintf(w, "  reason: %s", e.Reason)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "(+%d interpreter/library file reads, %d distinct syscalls)\n", libReads, syscalls)
	fmt.Fprintln(w, "sandbox destroyed")
}

func describe(e trace.Event) string {
	switch {
	case e.Destination != "":
		return e.Destination
	case e.Argv != "":
		return e.Argv
	case e.Event == trace.ProcessExit:
		return fmt.Sprintf("exit=%d", e.ExitCode)
	}
	return e.Path
}

func PrintFindings(w io.Writer, findings []policy.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "\nNo suspicious behaviour found.")
		return
	}
	fmt.Fprintln(w, "\n--- findings (excluded from proposal unless low) ---")
	for _, f := range findings {
		fmt.Fprintf(w, "[%-8s] %-22s %s\n", strings.ToUpper(f.Severity), f.Kind, f.Detail)
	}
}

// CrossCheck re-evaluates every observed event against the policy. With the
// Firecracker backend, eBPF evidence is independent of the in-guest agent, so
// a disagreement here means something slipped past in-guest enforcement.
func CrossCheck(t *trace.Trace, p *policy.Policy) []string {
	var out []string
	for _, e := range t.Events {
		if e.Action == "blocked" {
			continue
		}
		if ok, why := p.Evaluate(e); !ok {
			out = append(out, fmt.Sprintf("%s %s %s: %s", e.Source, e.Event, describe(e), why))
		}
	}
	return out
}

func PrintViolations(w io.Writer, v []string) {
	if len(v) == 0 {
		return
	}
	fmt.Fprintln(w, "\n--- observed but NOT prevented (investigate) ---")
	for _, s := range v {
		fmt.Fprintln(w, " ", s)
	}
}

func indentEnd(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
