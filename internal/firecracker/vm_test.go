package firecracker

import (
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Destroy must reap the VMM even when Wait was never called, and must tolerate
// being called twice (Start calls it on failure, the caller calls it on exit).
func TestDestroyReapsAndIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix process semantics")
	}
	v := New(Config{SocketPath: filepath.Join(t.TempDir(), "fc.sock")})
	v.cmd = exec.Command("sh", "-c", "sleep 30")
	v.console, v.pw = io.Pipe()
	if err := v.cmd.Start(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	v.Destroy()
	v.Destroy()
	if v.cmd.ProcessState == nil {
		t.Fatal("process was not reaped")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Destroy took %s; teardown must be bounded", elapsed)
	}
}

// Wait is used by the console goroutine and by Destroy; it must be safe to
// call repeatedly and must return the same result.
func TestWaitIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix process semantics")
	}
	v := New(Config{SocketPath: filepath.Join(t.TempDir(), "fc.sock")})
	v.cmd = exec.Command("sh", "-c", "exit 7")
	v.console, v.pw = io.Pipe()
	if err := v.cmd.Start(); err != nil {
		t.Fatal(err)
	}

	first := v.Wait()
	second := v.Wait()
	if first == nil {
		t.Fatal("expected a non-zero exit error")
	}
	if first != second {
		t.Fatalf("Wait results differ: %v vs %v", first, second)
	}
	v.Destroy()
}
