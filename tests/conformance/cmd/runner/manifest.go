package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Entry is a single row in known-gaps.yaml.
//
// Two shapes are accepted, discriminated by which fields are set:
//
//   - Go-native (Suite + ID):
//       suite: as_metadata
//       id:    TestDualPathParity/rfc8414_path_parity
//
//   - External suite (Suite + Plan + Test), e.g., OIDF, MCP:
//       suite: oidf
//       plan:  dynamic-op-basic
//       test:  dcr-rejects-non-https-redirect-uri
//
// Status is the expected outcome. Today the only legal value is "expected-fail";
// a passing test should not be in the manifest at all.
type Entry struct {
	Suite   string `yaml:"suite"`
	ID      string `yaml:"id,omitempty"`
	Plan    string `yaml:"plan,omitempty"`
	Test    string `yaml:"test,omitempty"`
	Status  string `yaml:"status"`
	Issue   int    `yaml:"issue"`
	Owner   string `yaml:"owner"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

// Key returns the runner's lookup key for this entry.
// Go-native entries: "<suite>::<id>"
// External entries:  "<suite>::<plan>::<test>"
func (e Entry) Key() string {
	if e.ID != "" {
		return e.Suite + "::" + e.ID
	}
	return e.Suite + "::" + e.Plan + "::" + e.Test
}

// Validate checks that an entry has all required fields and a parseable
// expires date. Returns the first violation found.
func (e Entry) Validate() error {
	if e.Suite == "" {
		return fmt.Errorf("suite is required")
	}
	if e.ID == "" && (e.Plan == "" || e.Test == "") {
		return fmt.Errorf("must set either id (Go-native) or both plan+test (external suite)")
	}
	if e.ID != "" && (e.Plan != "" || e.Test != "") {
		return fmt.Errorf("id is set; plan/test must be empty (cannot mix shapes)")
	}
	if e.Status != "expected-fail" {
		return fmt.Errorf("status must be \"expected-fail\" (got %q)", e.Status)
	}
	if e.Issue == 0 {
		return fmt.Errorf("issue is required")
	}
	if e.Owner == "" {
		return fmt.Errorf("owner is required")
	}
	if e.Reason == "" {
		return fmt.Errorf("reason is required")
	}
	if e.Expires == "" {
		return fmt.Errorf("expires is required")
	}
	if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
		return fmt.Errorf("expires must be ISO date YYYY-MM-DD (got %q)", e.Expires)
	}
	return nil
}

// LoadManifest reads and validates a known-gaps.yaml file, returning the
// entries indexed by Key.
func LoadManifest(path string) (map[string]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var raw []Entry
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	out := make(map[string]Entry, len(raw))
	for i, e := range raw {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("manifest entry %d (%s): %w", i, e.Key(), err)
		}
		k := e.Key()
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("manifest entry %d: duplicate key %s", i, k)
		}
		out[k] = e
	}
	return out, nil
}
