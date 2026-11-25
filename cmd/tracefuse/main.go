// Command tracefuse is the TraceFuse controller CLI.
//
//	tracefuse run --code task.py --mode observe
//	tracefuse policy approve trace-8f31a2
//	tracefuse run --code task.py --policy policy-8f31a2 --mode enforce
//	tracefuse diff trace-aaaaaa trace-bbbbbb
//	tracefuse report trace-8f31a2
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tracefuse/tracefuse/internal/diff"
	"github.com/tracefuse/tracefuse/internal/policy"
	"github.com/tracefuse/tracefuse/internal/report"
	"github.com/tracefuse/tracefuse/internal/sandbox"
	"github.com/tracefuse/tracefuse/internal/store"
)

func usage() {
	fmt.Fprint(os.Stderr, `TraceFuse - observe, learn, enforce.

Usage:
  tracefuse run --code FILE [--mode observe|enforce] [--policy ID] [--backend local|firecracker]
  tracefuse policy list|show|approve ID
  tracefuse diff TRACE_A TRACE_B
  tracefuse report TRACE
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func stateDir() string {
	if d := os.Getenv("TRACEFUSE_STATE"); d != "" {
		return d
	}
	return ".tracefuse"
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	code := fs.String("code", "", "Python file to execute")
	mode := fs.String("mode", "observe", "observe | enforce")
	policyID := fs.String("policy", "", "approved policy ID (enforce mode)")
	backend := fs.String("backend", envOr("TF_BACKEND", "local"), "local | firecracker")
	timeout := fs.Duration("timeout", 30*time.Second, "hard execution timeout")
	mem := fs.Int("memory-mb", 256, "guest memory limit")
	vcpus := fs.Int("vcpus", 1, "guest vCPUs")
	fcBin := fs.String("fc-bin", envOr("TF_FIRECRACKER", "firecracker"), "firecracker binary")
	kernel := fs.String("kernel", envOr("TF_KERNEL", "guest/out/vmlinux"), "guest kernel")
	rootfs := fs.String("rootfs", envOr("TF_ROOTFS", "guest/out/rootfs.ext4"), "guest rootfs image")
	tap := fs.String("tap", envOr("TF_TAP", ""), "host TAP device for guest networking (empty = no network)")
	mockHost := fs.String("mock-host", envOr("TF_MOCK_HOST", "127.0.0.1"), "address the demo workload calls (mock API)")
	trusted := fs.String("trusted-hosts", envOr("TF_TRUSTED_HOSTS", ""), "comma-separated hosts that may be learned even when private (e.g. TAP gateway)")
	python := fs.String("python", envOr("TF_PYTHON", "python3"), "python interpreter (local backend)")
	_ = fs.Parse(args)

	if *code == "" {
		return errors.New("--code is required")
	}
	if *mode != "observe" && *mode != "enforce" {
		return fmt.Errorf("unknown mode %q", *mode)
	}
	st := store.New(stateDir())

	var pol *policy.Policy
	if *mode == "enforce" {
		if *policyID == "" {
			return errors.New("enforce mode needs --policy")
		}
		p, err := st.LoadPolicy(*policyID)
		if err != nil {
			return err
		}
		if !p.Approved {
			return fmt.Errorf("policy %s is not approved. Review it, then run: tracefuse policy approve %s", p.ID, p.ID)
		}
		pol = p
		if p.Limits.TimeoutSec > 0 {
			*timeout = time.Duration(p.Limits.TimeoutSec) * time.Second
		}
		if p.Limits.MemoryMB > 0 {
			*mem = p.Limits.MemoryMB
		}
	}

	be, err := sandbox.New(*backend, sandbox.Options{
		Python: *python, FirecrackerBin: *fcBin, Kernel: *kernel, Rootfs: *rootfs, Tap: *tap,
		MockHost: *mockHost,
	})
	if err != nil {
		return err
	}
	job := sandbox.Job{
		ID: store.NewID("sb"), CodePath: *code, Mode: *mode, Policy: pol,
		Timeout: *timeout, MemoryMB: *mem, VCPUs: *vcpus,
	}
	tr, err := be.Run(context.Background(), job)
	if err != nil {
		return err
	}
	tr.ID = store.NewID("trace")
	tr.CodePath = *code
	if pol != nil {
		tr.PolicyID = pol.ID
	}
	if err := st.SaveTrace(tr); err != nil {
		return err
	}
	report.PrintRun(os.Stdout, tr)
	if pol != nil {
		report.PrintViolations(os.Stdout, report.CrossCheck(tr, pol))
	}

	if *mode == "observe" {
		p, findings := policy.ProposeWith(tr, policy.ProposeOptions{
			TrustedDestinations: splitList(*trusted),
		})
		p.ID = store.PolicyIDFor(tr.ID)
		if err := st.SavePolicy(p); err != nil {
			return err
		}
		report.PrintFindings(os.Stdout, findings)
		fmt.Printf("\nProposed policy %s saved (NOT approved).\n  review:  tracefuse policy show %s\n  approve: tracefuse policy approve %s\n", p.ID, p.ID, p.ID)
	}
	return nil
}

func cmdPolicy(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: tracefuse policy list|show|approve ID")
	}
	st := store.New(stateDir())
	switch args[0] {
	case "list":
		ids, err := st.ListPolicies()
		if err != nil {
			return err
		}
		for _, id := range ids {
			p, err := st.LoadPolicy(id)
			if err != nil {
				continue
			}
			fmt.Printf("%-20s approved=%-5v source=%s\n", p.ID, p.Approved, p.SourceTrace)
		}
		return nil
	case "show", "approve":
		if len(args) < 2 {
			return errors.New("policy ID required")
		}
		p, err := st.LoadPolicy(args[1])
		if err != nil {
			return err
		}
		if args[0] == "approve" {
			now := time.Now().UTC()
			p.Approved, p.ApprovedAt = true, &now
			if err := st.SavePolicy(p); err != nil {
				return err
			}
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(b))
		if args[0] == "approve" {
			fmt.Printf("\nApproved %s. Excluded findings were NOT added to the allowlist.\n", p.ID)
		}
		return nil
	}
	return fmt.Errorf("unknown policy command %q", args[0])
}

func cmdDiff(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tracefuse diff TRACE_A TRACE_B")
	}
	st := store.New(stateDir())
	a, err := st.LoadTrace(args[0])
	if err != nil {
		return err
	}
	b, err := st.LoadTrace(args[1])
	if err != nil {
		return err
	}
	diff.Compare(a, b).Write(os.Stdout)
	return nil
}

func cmdReport(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tracefuse report TRACE")
	}
	t, err := store.New(stateDir()).LoadTrace(args[0])
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(t, "", "  ")
	fmt.Println(string(b))
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// splitList accepts comma- or space-separated values and drops blanks.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
