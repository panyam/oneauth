package harness

import "strings"

// Result is the outcome of a single check inside an OIDF test run. The
// values mirror the harness's log-entry `result` field; INFO entries
// are routinely emitted alongside SUCCESS/FAILURE/WARNING and don't
// indicate any pass/fail decision.
type Result string

const (
	// ResultSuccess: the check ran and passed.
	ResultSuccess Result = "SUCCESS"
	// ResultFailure: the check ran and failed.
	ResultFailure Result = "FAILURE"
	// ResultWarning: the check could not evaluate one of its
	// preconditions (e.g., missing `scopes_supported` skipped the
	// "scopes_supported contains openid" check). Treated as a soft
	// failure for ratchet purposes — gaps the AS could fix.
	ResultWarning Result = "WARNING"
	// ResultInfo: informational; ignored by the ratchet.
	ResultInfo Result = "INFO"
)

// LogEntry is one line of the harness's structured log. The harness
// emits many of these per test run; ratchet logic cares about ones
// whose Result is FAILURE or WARNING. Src is the stable identifier
// (the check class — e.g., `OIDCCCheckDiscEndpointResponseTypesSupported`)
// that ratchet entries reference.
type LogEntry struct {
	Src    string `json:"src"`
	Result Result `json:"result"`
	Msg    string `json:"msg"`
	TestID string `json:"testId,omitempty"`
}

// CheckOutcome is one row of a TestSummary. Each Src may appear in the
// log multiple times (the harness re-runs some checks at different
// points); the summary collapses them to the worst outcome observed:
// FAILURE > WARNING > SUCCESS. The Msg field carries the first
// non-empty message at the worst severity, so failure detail is
// preserved in known-gaps.yaml diffing.
type CheckOutcome struct {
	Src    string
	Result Result
	Msg    string
}

// TestSummary aggregates a single OIDF test's log into one outcome per
// distinct Src. Use Summarize to build it from raw log entries.
type TestSummary struct {
	// Failures are checks whose worst observed outcome was FAILURE.
	Failures []CheckOutcome
	// Warnings are checks whose worst observed outcome was WARNING.
	Warnings []CheckOutcome
}

// Summarize collapses a flat log into per-Src outcomes, keeping only
// the ones that matter for ratcheting (FAILURE + WARNING). Order is
// preserved from first-appearance in the log so diffs against
// known-gaps.yaml stay stable across runs.
func Summarize(entries []LogEntry) TestSummary {
	type slot struct {
		idx     int
		outcome CheckOutcome
	}
	seen := map[string]slot{} // keyed by Src
	order := []string{}
	for _, e := range entries {
		// Ignore INFO and SUCCESS entries — only failures and warnings
		// drive ratchet state.
		if e.Result != ResultFailure && e.Result != ResultWarning {
			continue
		}
		// Ignore entries with no Src — they exist (e.g., the harness's
		// own progress notes) but can't be ratcheted because there's
		// no stable identifier.
		if strings.TrimSpace(e.Src) == "" {
			continue
		}
		current, ok := seen[e.Src]
		if !ok {
			seen[e.Src] = slot{
				idx:     len(order),
				outcome: CheckOutcome{Src: e.Src, Result: e.Result, Msg: e.Msg},
			}
			order = append(order, e.Src)
			continue
		}
		// Already seen — promote to worst severity. FAILURE outranks WARNING.
		if e.Result == ResultFailure && current.outcome.Result != ResultFailure {
			current.outcome.Result = ResultFailure
			current.outcome.Msg = e.Msg
			seen[e.Src] = current
		}
	}
	var sum TestSummary
	for _, src := range order {
		entry := seen[src].outcome
		switch entry.Result {
		case ResultFailure:
			sum.Failures = append(sum.Failures, entry)
		case ResultWarning:
			sum.Warnings = append(sum.Warnings, entry)
		}
	}
	return sum
}
