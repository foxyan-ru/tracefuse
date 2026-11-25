// Package store persists traces and policies as JSON files.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tracefuse/tracefuse/internal/policy"
	"github.com/tracefuse/tracefuse/internal/trace"
)

type Store struct{ Dir string }

func New(dir string) *Store { return &Store{Dir: dir} }

func NewID(prefix string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// PolicyIDFor maps trace-xxxx to policy-xxxx.
func PolicyIDFor(traceID string) string {
	return "policy-" + strings.TrimPrefix(traceID, "trace-")
}

func (s *Store) SaveTrace(t *trace.Trace) error {
	if err := writeJSON(filepath.Join(s.Dir, "traces", t.ID+".json"), t); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, "last_trace"), []byte(t.ID), 0o644)
}

func (s *Store) LoadTrace(idOrPath string) (*trace.Trace, error) {
	p := idOrPath
	if _, err := os.Stat(p); err != nil {
		p = filepath.Join(s.Dir, "traces", idOrPath+".json")
	}
	var t trace.Trace
	return &t, readJSON(p, &t)
}

func (s *Store) SavePolicy(p *policy.Policy) error {
	return writeJSON(filepath.Join(s.Dir, "policies", p.ID+".json"), p)
}

// LoadPolicy accepts a policy ID or the trace ID it was learned from.
func (s *Store) LoadPolicy(id string) (*policy.Policy, error) {
	if strings.HasPrefix(id, "trace-") {
		id = PolicyIDFor(id)
	}
	var p policy.Policy
	if err := readJSON(filepath.Join(s.Dir, "policies", id+".json"), &p); err != nil {
		return nil, fmt.Errorf("policy %s: %w", id, err)
	}
	return &p, nil
}

func (s *Store) ListPolicies() ([]string, error) {
	m, err := filepath.Glob(filepath.Join(s.Dir, "policies", "*.json"))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, f := range m {
		ids = append(ids, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	sort.Strings(ids)
	return ids, nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
