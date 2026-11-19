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
	// Result is PASSED, FAILED, WARNING, REVIEW, SKIPPED or UNKNOWN.
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

// Plan is one harness test plan as an exercise runs it: its name, the
// variant oneauth implements, and the JSON config the harness takes.
type Plan struct {
	Name    string
	Variant map[string]string
	Config  any
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
		r := runModule(ctx, h, planID, m, perModule)
		results = append(results, r)
		if progress != nil {
			progress(r)
		}
	}
	return planID, results, nil
}

func runModule(ctx context.Context, h *harness.Client, planID string, m harness.PlanModule, timeout time.Duration) ModuleResult {
	r := ModuleResult{Module: m.TestModule}
	testID, err := h.RunTest(ctx, planID, m.TestModule, m.Variant)
	if err != nil {
		r.Status, r.Result, r.Err = "ERROR", "UNKNOWN", err
		return r
	}
	r.TestID = testID
	mctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
