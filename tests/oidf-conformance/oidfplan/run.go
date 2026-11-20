// Package oidfplan runs an OpenID Foundation conformance-suite test plan
// against cmd/oneauth-server and judges each module against
// tests/conformance/known-gaps.yaml. The plan packages (fapi2, oidcc) build a
// Plan and register the clients it needs; this package does the rest, the
// same way for every plan.
package oidfplan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/panyam/oneauth/tests/oidf-conformance/harness"
)

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// SignUp creates the browser user (u) through the server's own signup form:
// fetch the form for its CSRF token and cookie, then post it back. An email
// that already exists answers the same way, so a rerun against a server
// still holding the user is fine.
func SignUp(ctx context.Context, hc *http.Client, serverURL string, u User) error {
	jar, _ := cookiejar.New(nil)
	c := *hc
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/auth/signup", nil)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("get signup form: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfField.FindSubmatch(body)
	if m == nil {
		return fmt.Errorf("signup form has no csrf_token field (status %d)", resp.StatusCode)
	}
	form := url.Values{}
	for k, v := range u.Profile {
		form[k] = v
	}
	form.Set("csrf_token", string(m[1]))
	form.Set("email", u.Email)
	form.Set("password", u.Password)
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", serverURL)
	resp, err = c.Do(req)
	if err != nil {
		return fmt.Errorf("post signup: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("signup answered %d", resp.StatusCode)
	}
	return nil
}

// Register posts body to the server's DCR endpoint and returns the client_id
// and, for a confidential client using a shared secret, the client_secret
// oneauth issued. A plan builds the RFC 7591 body for its own client type.
func Register(ctx context.Context, hc *http.Client, serverURL string, body map[string]any) (clientID, clientSecret string, err error) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/apps/dcr", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("dcr: %w", err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("dcr answered %d: %.300s", resp.StatusCode, answer)
	}
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(answer, &out); err != nil || out.ClientID == "" {
		return "", "", fmt.Errorf("dcr response has no client_id: %.300s", answer)
	}
	return out.ClientID, out.ClientSecret, nil
}

// ModuleResult is one plan module's outcome.
type ModuleResult struct {
	Module string
	TestID string
	// Status is the harness status (FINISHED, INTERRUPTED, WAITING, ...),
	// or TIMEOUT when the module didn't finish in time.
	Status string
	// Result is PASSED, FAILED, WARNING, REVIEW, SKIPPED or UNKNOWN from
	// the harness, or ResultManual for a module RunPlan didn't run.
	Result string
	// FirstFailure is the first FAILURE message in the module's log.
	FirstFailure string
	// Warnings are the module's WARNING messages, each as "Src: Msg".
	Warnings []string
	// ReviewPage is the page source the browser captured for the module's
	// REVIEW check, if it filled one. Passing modules carry REVIEW entries
	// too, with the placeholder marked no longer required and no page.
	ReviewPage string
	Err        error
}

// StatusNotRun and ResultManual mark a module RunPlan left out because it
// needs a person at the harness (StatusExpectedManual).
const (
	StatusNotRun = "NOT RUN"
	ResultManual = "MANUAL"
)

// Plan is one harness test plan as an exercise runs it: its name, the
// variant oneauth implements, and the JSON config the harness takes.
type Plan struct {
	Name string
	// Key names the run in known-gaps.yaml (an entry's plan) and in its run
	// record. Empty means Name. A plan run with several variants, such as
	// oidcc-test-plan once per client auth method, gives each run its own
	// Key so their entries and records stay apart.
	Key     string
	Variant map[string]string
	Config  any
	// Manual are modules RunPlan records as ResultManual without running
	// them, usually ManualModules of the plan's expectations.
	Manual map[string]bool
	// Actions are what a person would do for a module that stops in
	// CONFIGURED and waits for Start, keyed by module name. RunPlan runs
	// the action, then starts the module. oidcc-server-rotate-keys waits
	// like this for the server's keys to be rotated.
	Actions map[string]func(ctx context.Context) error
}

// ManifestKey is p.Key, or p.Name when Key is empty.
func (p Plan) ManifestKey() string {
	if p.Key != "" {
		return p.Key
	}
	return p.Name
}

// RunPlan creates the plan and runs each of its modules in turn, giving each
// up to perModule to finish. A module stuck waiting on the browser shows up
// as TIMEOUT rather than stopping the run. With only set, it runs just the
// modules whose names contain it.
func RunPlan(ctx context.Context, h *harness.Client, p Plan, perModule time.Duration, only string, progress func(ModuleResult)) (string, []ModuleResult, error) {
	planID, err := h.CreatePlanWithVariant(ctx, p.Name, p.Variant, p.Config)
	if err != nil {
		return "", nil, err
	}
	plan, err := h.GetPlan(ctx, planID)
	if err != nil {
		return planID, nil, err
	}
	var results []ModuleResult
	for _, m := range plan.Modules {
		if !strings.Contains(m.TestModule, only) {
			continue
		}
		r := runOrRecord(ctx, h, planID, m, p.Manual, p.Actions[m.TestModule], perModule)
		results = append(results, r)
		if progress != nil {
			progress(r)
		}
	}
	return planID, results, nil
}

// runOrRecord runs m, or records it as manual without touching the
// harness when manual lists it.
func runOrRecord(ctx context.Context, h *harness.Client, planID string, m harness.PlanModule, manual map[string]bool, action func(context.Context) error, timeout time.Duration) ModuleResult {
	if manual[m.TestModule] {
		return ModuleResult{Module: m.TestModule, Status: StatusNotRun, Result: ResultManual}
	}
	return runModule(ctx, h, planID, m, action, timeout)
}

func runModule(ctx context.Context, h *harness.Client, planID string, m harness.PlanModule, action func(context.Context) error, timeout time.Duration) ModuleResult {
	r := ModuleResult{Module: m.TestModule}
	testID, err := h.RunTest(ctx, planID, m.TestModule, m.Variant)
	if err != nil {
		r.Status, r.Result, r.Err = "ERROR", "UNKNOWN", err
		return r
	}
	r.TestID = testID
	mctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if action != nil {
		if err := actThenStart(mctx, h, testID, action); err != nil {
			r.Status, r.Result, r.Err = "ERROR", "UNKNOWN", err
			return r
		}
	}
	info, err := h.WaitForCompletion(mctx, testID)
	if err != nil {
		r.Status, r.Result = "TIMEOUT", "UNKNOWN"
		if last, ierr := h.GetInfo(ctx, testID); ierr == nil {
			r.Status = "TIMEOUT (" + last.Status + ")"
		}
	} else {
		r.Status, r.Result = info.Status, info.Result
	}
	if entries, lerr := h.GetLog(ctx, testID); lerr == nil {
		for _, e := range entries {
			if e.Result == harness.ResultFailure && r.FirstFailure == "" {
				r.FirstFailure = e.Src + ": " + e.Msg
			}
			if e.Result == harness.ResultWarning {
				r.Warnings = append(r.Warnings, e.Src+": "+e.Msg)
			}
			if e.Result == harness.ResultReview && e.PageSource != "" && r.ReviewPage == "" {
				r.ReviewPage = e.PageSource
			}
		}
	}
	return r
}

// actThenStart waits for testID to reach CONFIGURED, the state of a module
// waiting for its Start button, runs action, and presses Start.
func actThenStart(ctx context.Context, h *harness.Client, testID string, action func(context.Context) error) error {
	for {
		info, err := h.GetInfo(ctx, testID)
		if err != nil {
			return err
		}
		if info.Status == "CONFIGURED" {
			break
		}
		if info.Status == "FINISHED" || info.Status == "INTERRUPTED" {
			return fmt.Errorf("module ended (%s) before it waited to be started", info.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err := action(ctx); err != nil {
		return fmt.Errorf("module action: %w", err)
	}
	return h.StartTest(ctx, testID)
}

// RotateServerKeys is the action for oidcc-server-rotate-keys: it asks the
// oneauth-server at serverURL to rotate its signing key, through POST
// /admin/signing-key/rotate (jwt.key_rotation on, issue 507).
func RotateServerKeys(hc *http.Client, serverURL string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/admin/signing-key/rotate", nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("rotate signing key: status %d", resp.StatusCode)
		}
		return nil
	}
}
