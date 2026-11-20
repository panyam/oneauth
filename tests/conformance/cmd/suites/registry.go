package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Suite kinds. A gating suite's failure fails `make conformance`; an info
// suite is reported and never fails the run. A manual suite is run by a
// person (OAuch has no API, issue 497): make conformance never runs it,
// and its entry records the last run.
const (
	KindGating = "gating"
	KindInfo   = "info"
	KindManual = "manual"
)

// ManualRun is a manual suite's last run, as its suites.yaml entry records
// it.
type ManualRun struct {
	// Date is when the run happened, YYYY-MM-DD.
	Date string `yaml:"date"`
	// Commit is the oneauth commit the run tested.
	Commit string `yaml:"commit"`
	// Result is the one-line outcome the report shows.
	Result string `yaml:"result"`
	// Doc is where the run is written up and its findings triaged.
	Doc string `yaml:"doc"`
}

// Suite is one entry in conformance/suites.yaml.
type Suite struct {
	Name     string   `yaml:"name"`
	Kind     string   `yaml:"kind"`
	Covers   string   `yaml:"covers"`
	Source   string   `yaml:"source"`
	Needs    []string `yaml:"needs"`
	Tracking string   `yaml:"tracking"`
	Note     string   `yaml:"note"`
	// Plan names the OIDF plan an exercise suite runs. The exercise writes
	// its run record to <results dir>/<plan>.json, and the report shows
	// the plan's modules.
	Plan string `yaml:"plan"`
	// Timeout bounds one run of the suite, as a Go duration ("15m").
	// Empty uses DefaultTimeout.
	Timeout string `yaml:"timeout"`
	// LastRun records a manual suite's last run. Required for kind manual,
	// and refused on any other kind.
	LastRun *ManualRun `yaml:"last_run"`
}

// DefaultTimeout bounds a suite whose entry sets no timeout.
const DefaultTimeout = 20 * time.Minute

// RunTimeout is the suite's timeout, or DefaultTimeout. Validate has
// already refused an entry whose timeout doesn't parse.
func (s Suite) RunTimeout() time.Duration {
	if d, err := time.ParseDuration(s.Timeout); err == nil && d > 0 {
		return d
	}
	return DefaultTimeout
}

// Target is the suite's conformance/Makefile target.
func (s Suite) Target() string { return "conf-" + s.Name }

// MissingEnv returns the first "env:VAR" prerequisite getenv reports
// unset, or "".
func (s Suite) MissingEnv(getenv func(string) string) string {
	for _, n := range s.Needs {
		if v, ok := strings.CutPrefix(n, "env:"); ok && getenv(v) == "" {
			return v
		}
	}
	return ""
}

// Registry is conformance/suites.yaml.
type Registry struct {
	Suites []Suite `yaml:"suites"`
}

// LoadRegistry reads and parses the registry at path.
func LoadRegistry(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

var suiteName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Validate returns one line per problem with the entries themselves:
// a name that isn't lower-case-with-dashes or appears twice, an unknown
// kind, an empty covers, or an env prerequisite that names no variable.
func (r *Registry) Validate() []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range r.Suites {
		if !suiteName.MatchString(s.Name) {
			out = append(out, fmt.Sprintf("%q: name must be lower-case words joined by dashes", s.Name))
		}
		if seen[s.Name] {
			out = append(out, fmt.Sprintf("%q appears twice", s.Name))
		}
		seen[s.Name] = true
		if s.Kind != KindGating && s.Kind != KindInfo && s.Kind != KindManual {
			out = append(out, fmt.Sprintf("%q: kind must be gating, info or manual (got %q)", s.Name, s.Kind))
		}
		if s.Kind == KindManual && (s.LastRun == nil || s.LastRun.Date == "" || s.LastRun.Result == "") {
			out = append(out, fmt.Sprintf("%q: a manual suite needs last_run with a date and a result", s.Name))
		}
		if s.Kind != KindManual && s.LastRun != nil {
			out = append(out, fmt.Sprintf("%q: last_run is for manual suites only", s.Name))
		}
		if strings.TrimSpace(s.Covers) == "" {
			out = append(out, fmt.Sprintf("%q: covers is empty", s.Name))
		}
		if s.Timeout != "" {
			if d, err := time.ParseDuration(s.Timeout); err != nil || d <= 0 {
				out = append(out, fmt.Sprintf("%q: timeout %q is not a duration", s.Name, s.Timeout))
			}
		}
		for _, n := range s.Needs {
			if v, ok := strings.CutPrefix(n, "env:"); ok && v == "" {
				out = append(out, fmt.Sprintf("%q: need %q names no variable", s.Name, n))
			}
		}
	}
	return out
}

var confTarget = regexp.MustCompile(`^(conf-[a-z0-9-]+):`)

// MakeTargets returns the conf-* targets defined in the Makefile at path.
func MakeTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := confTarget.FindStringSubmatch(sc.Text()); m != nil {
			out = append(out, m[1])
		}
	}
	return out, sc.Err()
}

// Drift returns one line per disagreement between the registry and the
// Makefile's conf-* targets, in both directions, so a suite can't be added
// to one without the other.
func Drift(r *Registry, targets []string) []string {
	var out []string
	has := map[string]bool{}
	for _, t := range targets {
		has[t] = true
	}
	named := map[string]bool{}
	for _, s := range r.Suites {
		if s.Kind == KindManual {
			continue // run by a person, so no target
		}
		named[s.Target()] = true
		if !has[s.Target()] {
			out = append(out, fmt.Sprintf("suite %q has no %s target in conformance/Makefile", s.Name, s.Target()))
		}
	}
	for _, t := range targets {
		if !named[t] {
			out = append(out, fmt.Sprintf("%s has no entry in conformance/suites.yaml", t))
		}
	}
	return out
}
