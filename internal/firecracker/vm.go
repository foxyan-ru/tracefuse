// Package firecracker drives one Firecracker microVM through its REST API
// over a Unix socket. No SDK dependency, so every call is visible.
package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

type Config struct {
	Binary         string
	SocketPath     string
	KernelPath     string
	RootfsPath     string
	WorkspaceImage string
	VCPUs          int
	MemoryMB       int
	TapDevice      string // empty = no network interface at all
	BootArgs       string
}

const defaultBootArgs = "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/tracefuse-init"

type VM struct {
	cfg     Config
	cmd     *exec.Cmd
	console *io.PipeReader
	pw      *io.PipeWriter
	http    *http.Client

	waitOnce sync.Once
	waitErr  error
}

func New(cfg Config) *VM {
	if cfg.BootArgs == "" {
		cfg.BootArgs = defaultBootArgs
	}
	return &VM{cfg: cfg}
}

// Console streams the guest serial console (ttyS0 is wired to stdout).
func (v *VM) Console() io.Reader { return v.console }

func (v *VM) Start(ctx context.Context) error {
	_ = os.Remove(v.cfg.SocketPath)
	v.console, v.pw = io.Pipe()
	v.cmd = exec.Command(v.cfg.Binary, "--api-sock", v.cfg.SocketPath)
	v.cmd.Stdout, v.cmd.Stderr = v.pw, v.pw
	if err := v.cmd.Start(); err != nil {
		_ = v.pw.Close()
		return err
	}
	if err := waitForSocket(ctx, v.cfg.SocketPath, 3*time.Second); err != nil {
		v.Destroy()
		return err
	}
	v.http = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", v.cfg.SocketPath)
		}},
	}

	steps := []struct {
		path string
		body any
	}{
		{"/machine-config", map[string]any{"vcpu_count": v.cfg.VCPUs, "mem_size_mib": v.cfg.MemoryMB, "smt": false}},
		{"/boot-source", map[string]any{"kernel_image_path": v.cfg.KernelPath, "boot_args": v.cfg.BootArgs}},
		{"/drives/rootfs", map[string]any{"drive_id": "rootfs", "path_on_host": v.cfg.RootfsPath, "is_root_device": true, "is_read_only": false}},
		{"/drives/workspace", map[string]any{"drive_id": "workspace", "path_on_host": v.cfg.WorkspaceImage, "is_root_device": false, "is_read_only": false}},
	}
	if v.cfg.TapDevice != "" {
		steps = append(steps, struct {
			path string
			body any
		}{"/network-interfaces/eth0", map[string]any{"iface_id": "eth0", "guest_mac": "06:00:AC:10:00:02", "host_dev_name": v.cfg.TapDevice}})
	}
	for _, s := range steps {
		if err := v.call(ctx, http.MethodPut, s.path, s.body); err != nil {
			v.Destroy()
			return err
		}
	}
	if err := v.call(ctx, http.MethodPut, "/actions", map[string]any{"action_type": "InstanceStart"}); err != nil {
		v.Destroy()
		return err
	}
	return nil
}

// Wait blocks until the Firecracker process exits (guest reboot=k exits it).
// It is safe to call more than once; the process is reaped only once.
func (v *VM) Wait() error {
	v.waitOnce.Do(func() {
		if v.cmd != nil {
			v.waitErr = v.cmd.Wait()
		}
		if v.pw != nil {
			_ = v.pw.Close()
		}
	})
	return v.waitErr
}

// Destroy kills the VMM, reaps it and removes its socket. It is idempotent and
// bounded: a stuck process cannot block teardown for more than five seconds.
func (v *VM) Destroy() {
	if v.cmd != nil && v.cmd.Process != nil {
		_ = v.cmd.Process.Kill()
	}
	if v.pw != nil {
		_ = v.pw.Close()
	}
	if v.cmd != nil {
		done := make(chan struct{})
		go func() {
			_ = v.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	_ = os.Remove(v.cfg.SocketPath)
}

// CreateSnapshot pauses the VM and writes a full snapshot (week 6+ feature:
// boot once, snapshot after the observer attaches, restore for each run).
func (v *VM) CreateSnapshot(ctx context.Context, snapPath, memPath string) error {
	if err := v.call(ctx, http.MethodPatch, "/vm", map[string]any{"state": "Paused"}); err != nil {
		return err
	}
	return v.call(ctx, http.MethodPut, "/snapshot/create", map[string]any{
		"snapshot_type": "Full", "snapshot_path": snapPath, "mem_file_path": memPath,
	})
}

// LoadSnapshot restores a snapshot into a freshly started (unconfigured) VMM.
func (v *VM) LoadSnapshot(ctx context.Context, snapPath, memPath string) error {
	return v.call(ctx, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": snapPath,
		"mem_backend":   map[string]any{"backend_type": "File", "backend_path": memPath},
		"resume_vm":     true,
	})
}

func (v *VM) call(ctx context.Context, method, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	return nil
}

func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return fmt.Errorf("firecracker API socket %s did not appear", path)
}
