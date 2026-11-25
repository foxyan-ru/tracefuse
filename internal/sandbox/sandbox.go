// Package sandbox runs one workload in one disposable environment.
package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tracefuse/tracefuse/internal/policy"
	"github.com/tracefuse/tracefuse/internal/trace"
)

type Job struct {
	ID       string
	CodePath string
	Mode     string // observe | enforce
	Policy   *policy.Policy
	Timeout  time.Duration
	MemoryMB int
	VCPUs    int
}

type Backend interface {
	Run(ctx context.Context, job Job) (*trace.Trace, error)
}

type Options struct {
	Python         string
	FirecrackerBin string
	Kernel         string
	Rootfs         string
	Tap            string
}

// New returns a backend by name.
//
//	firecracker: the real thing. KVM microVM, guest eBPF, nftables enforcement.
//	local:       developer loop on a laptop. NOT a security boundary.
func New(name string, o Options) (Backend, error) {
	switch name {
	case "local":
		return &localBackend{python: o.Python}, nil
	case "firecracker":
		return &fcBackend{bin: o.FirecrackerBin, kernel: o.Kernel, rootfs: o.Rootfs, tap: o.Tap}, nil
	}
	return nil, fmt.Errorf("unknown backend %q", name)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
