package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Gap is one tests/conformance/known-gaps.yaml entry as the report shows
// it. Class is "open" (a gap with an open issue) or "accepted" (an outcome
// kept on purpose, with Reason saying why). The report carries the whole
// list, so a reader sees every expected outcome without opening the YAML.
type Gap struct {
	Suite  string   `json:"suite"`
	Check  string   `json:"check"`
	Plans  []string `json:"plans,omitempty"`
	Status string   `json:"status"`
	Class  string   `json:"class"`
	Issue  int      `json:"issue"`
	Reason string   `json:"reason"`
}

// LoadGaps reads the manifest at path in file order. An entry without a
// class is an error, the same rule the native runner enforces.
func LoadGaps(path string) ([]Gap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Suite  string   `yaml:"suite"`
		ID     string   `yaml:"id"`
		Plan   string   `yaml:"plan"`
		Plans  []string `yaml:"plans"`
		Test   string   `yaml:"test"`
		Status string   `yaml:"status"`
		Class  string   `yaml:"class"`
		Issue  int      `yaml:"issue"`
		Reason string   `yaml:"reason"`
	}
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	gaps := make([]Gap, 0, len(entries))
	for _, e := range entries {
		if e.Class != "open" && e.Class != "accepted" {
			return nil, fmt.Errorf("%s: entry %s%s has class %q, want open or accepted", path, e.ID, e.Test, e.Class)
		}
		g := Gap{Suite: e.Suite, Check: e.Test, Plans: e.Plans, Status: e.Status, Class: e.Class, Issue: e.Issue, Reason: strings.TrimSpace(e.Reason)}
		if e.ID != "" {
			g.Check = e.ID
		}
		if e.Plan != "" {
			g.Plans = []string{e.Plan}
		}
		gaps = append(gaps, g)
	}
	return gaps, nil
}

// gapFor returns the gap a plan's module row matches, if any.
func gapFor(gaps []Gap, plan, module string) *Gap {
	for i := range gaps {
		g := &gaps[i]
		if g.Check != module {
			continue
		}
		for _, p := range g.Plans {
			if p == plan {
				return g
			}
		}
	}
	return nil
}

// renderGaps writes the report's "Known gaps" section: a count per class,
// then one row per entry, open gaps first.
func renderGaps(b *strings.Builder, gaps []Gap) {
	if len(gaps) == 0 {
		return
	}
	byClass := map[string]int{}
	for _, g := range gaps {
		byClass[g.Class]++
	}
	b.WriteString("\n## Known gaps\n\n")
	fmt.Fprintf(b, "`tests/conformance/known-gaps.yaml` lists %d expected outcomes. ", len(gaps))
	fmt.Fprintf(b, "%d are open gaps, and each names an open issue. ", byClass["open"])
	fmt.Fprintf(b, "%d are accepted: oneauth keeps that outcome on purpose, and the reason says why. ", byClass["accepted"])
	b.WriteString("An accepted entry's issue is where the decision was made, so it may be closed. ")
	b.WriteString("Anything that isn't a pass, and isn't listed here, fails its suite.\n\n")
	b.WriteString("| Class | Suite | Check | Expected | Issue | Reason |\n|---|---|---|---|---|---|\n")
	sorted := append([]Gap(nil), gaps...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Class == "open" && sorted[j].Class != "open" })
	for _, g := range sorted {
		check := "`" + g.Check + "`"
		if len(g.Plans) > 0 {
			check += " (" + plural(len(g.Plans), "plan") + ")"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %d | %s |\n", g.Class, g.Suite, cell(check, 0), g.Status, g.Issue, cell(g.Reason, 0))
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
