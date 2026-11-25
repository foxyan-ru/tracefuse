package sandbox

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tracefuse/tracefuse/internal/trace"
)

//go:embed tracer.py
var tracerSrc []byte

// TracerSource is shared with the guest image build.
func TracerSource() []byte { return tracerSrc }

// localBackend runs the workload as a host process under the Python audit-hook
// tracer. Use it to develop the observe -> propose -> approve -> enforce loop
// without KVM. It shares the host kernel: never run untrusted code with it.
type localBackend struct {
	python   string
	mockHost string
}

func (l *localBackend) Run(ctx context.Context, job Job) (*trace.Trace, error) {
	root, err := os.MkdirTemp("", "tracefuse-"+job.ID+"-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root) // disposable: nothing survives the run

	ws, tmp := filepath.Join(root, "workspace"), filepath.Join(root, "tmp")
	for _, d := range []string{ws, tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := copyFile(job.CodePath, filepath.Join(ws, "main.py")); err != nil {
		return nil, fmt.Errorf("copy workload: %w", err)
	}
	tracer := filepath.Join(root, "tracer.py")
	if err := os.WriteFile(tracer, tracerSrc, 0o644); err != nil {
		return nil, err
	}
	events := filepath.Join(root, "events.jsonl")

	// Minimal environment: no host secrets, tokens or cloud credentials leak in.
	env := []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + tmp, "TMPDIR=" + tmp, "LANG=C.UTF-8",
		"TF_MODE=" + job.Mode, "TF_SANDBOX_ID=" + job.ID, "TF_EVENTS=" + events,
		"TF_WORKSPACE=" + ws, "TF_TMP=" + tmp, fmt.Sprintf("TF_MEMORY_MB=%d", job.MemoryMB),
		"TF_MOCK_HOST=" + mockHostOr(l.mockHost),
	}
	if job.Policy != nil {
		pf := filepath.Join(root, "policy.json")
		b, _ := json.Marshal(job.Policy)
		if err := os.WriteFile(pf, b, 0o600); err != nil {
			return nil, err
		}
		env = append(env, "TF_POLICY="+pf)
	}

	runCtx, cancel := context.WithTimeout(ctx, job.Timeout)
	defer cancel()
	// -I: isolated mode (ignore PYTHON* env, user site). -B: no .pyc writes.
	cmd := exec.CommandContext(runCtx, l.python, "-I", "-B", tracer, filepath.Join(ws, "main.py"))
	cmd.Dir, cmd.Env = ws, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	start := time.Now()
	runErr := cmd.Run()
	tr := &trace.Trace{
		SandboxID: job.ID, Mode: job.Mode, Backend: "local", StartedAt: start.UTC(),
		DurationMS: time.Since(start).Milliseconds(), Stdout: stdout.String(), Stderr: stderr.String(),
	}
	var exitErr *exec.ExitError
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		tr.TimedOut, tr.ExitCode = true, -1
	case errors.As(runErr, &exitErr):
		tr.ExitCode = exitErr.ExitCode()
	case runErr != nil:
		return nil, fmt.Errorf("start workload: %w", runErr)
	}
	if f, err := os.Open(events); err == nil {
		tr.Events = trace.ReadJSONL(f, job.ID)
		f.Close()
	}
	return tr, nil
}
