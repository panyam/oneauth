package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// writeReport emits a Markdown summary of a runner invocation, suitable
// for checking into test-reports/. It's purely advisory — exit codes
// drive CI, the report is for humans reading the gap surface.
func writeReport(path string, results []Result, manifest map[string]Entry, issues []Issue) error {
	var b strings.Builder

	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	fmt.Fprintf(&b, "# OneAuth Conformance Report\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", now)

	pass, fail, skip, gapped := 0, 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		}
		if _, ok := manifest[r.Key()]; ok {
			gapped++
		}
	}

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| Tests run | %d |\n", len(results))
	fmt.Fprintf(&b, "| Passing | %d |\n", pass)
	fmt.Fprintf(&b, "| Failing | %d |\n", fail)
	fmt.Fprintf(&b, "| Skipped (forbidden) | %d |\n", skip)
	fmt.Fprintf(&b, "| Known gaps in manifest | %d |\n", len(manifest))
	fmt.Fprintf(&b, "| Gapped tests observed | %d |\n", gapped)
	fmt.Fprintf(&b, "| Ratchet issues | %d |\n\n", len(issues))

	if len(issues) > 0 {
		fmt.Fprintf(&b, "## Ratchet issues\n\n")
		b.WriteString("```\n")
		b.WriteString(FormatIssues(issues))
		b.WriteString("```\n\n")
	}

	type gapRow struct {
		key     string
		entry   Entry
		expired bool
	}
	var rows []gapRow
	today := time.Now().UTC()
	for k, e := range manifest {
		exp, _ := time.Parse("2006-01-02", e.Expires)
		rows = append(rows, gapRow{key: k, entry: e, expired: exp.Before(today)})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].entry.Expires < rows[j].entry.Expires
	})

	if len(rows) > 0 {
		fmt.Fprintf(&b, "## Known gaps (sorted by expires, oldest first)\n\n")
		fmt.Fprintf(&b, "| Expires | Suite | Test | Issue | Owner | Status |\n")
		fmt.Fprintf(&b, "|---|---|---|---|---|---|\n")
		for _, row := range rows {
			ident := row.entry.ID
			if ident == "" {
				ident = row.entry.Plan + "/" + row.entry.Test
			}
			marker := ""
			if row.expired {
				marker = " ⚠ expired"
			}
			fmt.Fprintf(&b, "| %s%s | %s | `%s` | %d | %s | %s |\n",
				row.entry.Expires, marker, row.entry.Suite, ident,
				row.entry.Issue, row.entry.Owner, row.entry.Status)
		}
		b.WriteString("\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}
