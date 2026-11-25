package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tracefuse/tracefuse/internal/firecracker"
	"github.com/tracefuse/tracefuse/internal/trace"
)

// fcBackend runs each job in a fresh Firecracker microVM.
//
// Channel: the guest writes tagged lines to its serial console (ttyS0):
//
//	TFEVT {json}   one event from the eBPF observer or policy agent
//	TFOUT text     workload stdout/stderr
//	TFEXIT n       workload exit status
//	... TFBLOCK    kernel log line from an nftables drop
//
// Everything from the guest is treated as untrusted input.
type fcBackend struct{ bin, kernel, rootfs, tap string }

func (b *fcBackend) Run(ctx context.Context, job Job) (*trace.Trace, error) {
	root, err := os.MkdirTemp("", "tracefuse-fc-"+job.ID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)

	ws := filepath.Join(root, "workspace")
	meta := filepath.Join(ws, ".tracefuse")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		return nil, err
	}
	if err := copyFile(job.CodePath, filepath.Join(ws, "main.py")); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(meta, "mode"), []byte(job.Mode), 0o644); err != nil {
		return nil, err
	}
	if job.Policy != nil {
		pj, _ := json.MarshalIndent(job.Policy, "", "  ")
		rules, hosts, err := job.Policy.NetworkArtifacts()
		if err != nil {
			return nil, err
		}
		sc, err := job.Policy.SeccompProfile()
		if err != nil {
			return nil, err
		}
		for name, data := range map[string]string{"policy.json": string(pj), "nft.rules": rules, "hosts": hosts, "seccomp.json": string(sc)} {
			if err := os.WriteFile(filepath.Join(meta, name), []byte(data), 0o644); err != nil {
				return nil, err
			}
		}
	}

	// Workspace travels in as a second block device built from the directory.
	wsImg := filepath.Join(root, "workspace.ext4")
	if out, err := exec.CommandContext(ctx, "mkfs.ext4", "-q", "-d", ws, wsImg, "64M").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("mkfs.ext4: %v: %s", err, out)
	}
	// Disposable root filesystem: a private copy per VM.
	rootfs := filepath.Join(root, "rootfs.ext4")
	if err := copyFile(b.rootfs, rootfs); err != nil {
		return nil, fmt.Errorf("copy rootfs: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, job.Timeout)
	defer cancel()

	vm := firecracker.New(firecracker.Config{
		Binary: b.bin, SocketPath: filepath.Join(root, "fc.sock"),
		KernelPath: b.kernel, RootfsPath: rootfs, WorkspaceImage: wsImg,
		VCPUs: job.VCPUs, MemoryMB: job.MemoryMB, TapDevice: b.tap,
	})
	start := time.Now()
	if err := vm.Start(runCtx); err != nil {
		vm.Destroy()
		return nil, fmt.Errorf("start microVM: %w", err)
	}
	defer vm.Destroy()

	tr := &trace.Trace{SandboxID: job.ID, Mode: job.Mode, Backend: "firecracker", StartedAt: start.UTC(), ExitCode: -1}
	var stdout strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(vm.Console())
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			handleConsoleLine(tr, &stdout, sc.Text())
		}
	}()

	waitErr := make(chan error, 1)
	go func() { waitErr <- vm.Wait() }()
	select {
	case <-waitErr:
	case <-runCtx.Done():
		tr.TimedOut = true
		vm.Destroy()
		<-waitErr
	}
	<-done
	tr.DurationMS = time.Since(start).Milliseconds()
	tr.Stdout = stdout.String()
	return tr, nil
}

const consoleTail = 40

func handleConsoleLine(tr *trace.Trace, out *strings.Builder, line string) {
	line = strings.TrimRight(line, "\r")
	switch {
	case strings.HasPrefix(line, "TFEVT "):
		var e trace.Event
		if json.Unmarshal([]byte(line[len("TFEVT "):]), &e) == nil {
			tr.Events = append(tr.Events, trace.Normalize(e, tr.SandboxID))
		}
	case strings.HasPrefix(line, "TFOUT "):
		out.WriteString(line[len("TFOUT "):] + "\n")
	case strings.HasPrefix(line, "TFEXIT "):
		fmt.Sscanf(line[len("TFEXIT "):], "%d", &tr.ExitCode)
	case strings.Contains(line, "TFBLOCK "):
		if e, ok := parseNFLog(line); ok {
			tr.Events = append(tr.Events, trace.Normalize(e, tr.SandboxID))
		}
	default:
		tr.ConsoleTail = append(tr.ConsoleTail, line)
		if len(tr.ConsoleTail) > consoleTail {
			tr.ConsoleTail = tr.ConsoleTail[1:]
		}
	}
}

// parseNFLog turns "TFBLOCK IN= OUT=eth0 SRC=.. DST=1.2.3.4 ... DPT=443" into an event.
func parseNFLog(line string) (trace.Event, bool) {
	var dst, dpt string
	for _, f := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(f, "DST="); ok {
			dst = v
		}
		if v, ok := strings.CutPrefix(f, "DPT="); ok {
			dpt = v
		}
	}
	if dst == "" {
		return trace.Event{}, false
	}
	return trace.Event{
		Event: trace.NetworkConnect, Source: "nftables", Process: "kernel",
		Destination: dst + ":" + dpt, Action: "blocked", Reason: "kernel nftables: destination not in policy",
	}, true
}
