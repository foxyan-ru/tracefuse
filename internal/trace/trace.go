// Package trace defines the TraceFuse event schema and trace files.
package trace

import (
	"bufio"
	"encoding/json"
	"io"
	"time"
)

// Event types emitted by the guest observer and policy agent.
const (
	Exec           = "exec"
	FileOpen       = "file_open"
	NetworkConnect = "network_connect"
	DNS            = "dns"
	ProcessExit    = "process_exit"
	Syscall        = "syscall" // first use of a syscall number (eBPF raw_syscalls)
	PrivChange     = "priv_change"
	Mount          = "mount"
)

// Event is one observed or blocked action inside the sandbox.
type Event struct {
	SandboxID   string    `json:"sandbox_id"`
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`
	Source      string    `json:"source,omitempty"` // ebpf | audit | nftables
	Process     string    `json:"process"`
	PID         int       `json:"pid"`
	Path        string    `json:"path,omitempty"`
	Argv        string    `json:"argv,omitempty"`
	Flags       string    `json:"flags,omitempty"` // "r", "w", or raw open(2) flags from eBPF
	Destination string    `json:"destination,omitempty"`
	ExitCode    int       `json:"exit_code,omitempty"`
	SyscallNr   int       `json:"syscall_nr,omitempty"`
	Action      string    `json:"action"` // observed | blocked
	Reason      string    `json:"reason,omitempty"`
}

// Trace is the full record of one disposable sandbox execution.
type Trace struct {
	ID          string    `json:"id"`
	SandboxID   string    `json:"sandbox_id"`
	CodePath    string    `json:"code_path"`
	Mode        string    `json:"mode"`
	Backend     string    `json:"backend"`
	PolicyID    string    `json:"policy_id,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	DurationMS  int64     `json:"duration_ms"`
	ExitCode    int       `json:"exit_code"`
	TimedOut    bool      `json:"timed_out"`
	Stdout      string    `json:"stdout"`
	Stderr      string    `json:"stderr,omitempty"`
	ConsoleTail []string  `json:"console_tail,omitempty"`
	Events      []Event   `json:"events"`
}

// ReadJSONL parses newline-delimited JSON events. Malformed lines are skipped,
// because the guest is untrusted and may write garbage to the channel.
func ReadJSONL(r io.Reader, sandboxID string) []Event {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		out = append(out, Normalize(e, sandboxID))
	}
	return out
}

// Normalize fills controller-owned fields. The sandbox ID always comes from
// the controller, never from the guest.
func Normalize(e Event, sandboxID string) Event {
	e.SandboxID = sandboxID
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Action == "" {
		e.Action = "observed"
	}
	return e
}
