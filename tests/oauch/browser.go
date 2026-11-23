package oauch

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"time"

	"github.com/mxschmitt/playwright-go"
)

// Run drives one OAuch run through its dashboard in a headless Chromium.
type Run struct {
	// OAuchURL is OAuch's base URL, such as https://localhost:9443.
	OAuchURL string
	// ASHost is host:port of oneauth-server as the browser sees it. Popups
	// on this host get logged in, approved, or marked stalled.
	ASHost string
	// Username and Password sign in to oneauth-server in the popups.
	Username, Password string
	// Logf receives progress lines.
	Logf func(format string, args ...any)

	pw      *playwright.Playwright
	browser playwright.Browser
	page    playwright.Page
}

// Start launches Chromium and signs in to OAuch. Visiting OAuch's home
// page signs the browser in as a throwaway user.
func (r *Run) Start() error {
	if r.Logf == nil {
		r.Logf = log.Printf
	}
	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("start playwright (install it with `make oauch-browser`): %w", err)
	}
	r.pw = pw
	r.browser, err = pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true)})
	if err != nil {
		return fmt.Errorf("launch chromium: %w", err)
	}
	// Both servers use the OIDF harness's test certificate.
	bctx, err := r.browser.NewContext(playwright.BrowserNewContextOptions{IgnoreHttpsErrors: playwright.Bool(true)})
	if err != nil {
		return err
	}
	if r.page, err = bctx.NewPage(); err != nil {
		return err
	}
	_, err = r.page.Goto(r.OAuchURL + "/")
	return err
}

// Close shuts the browser and the Playwright driver down.
func (r *Run) Close() {
	if r.browser != nil {
		_ = r.browser.Close()
	}
	if r.pw != nil {
		_ = r.pw.Stop()
	}
}

// siteLink matches a site in the dashboard's sidebar list: a link to the
// site's results with its name in a <p>.
var siteLink = regexp.MustCompile(`href="/Dashboard/Results/([0-9a-f-]{36})"[^>]*>(?:\s|<i[^>]*></i>)*<p>([^<]+)</p>`)

// siteID returns the ID of the site named name in the dashboard's HTML.
func siteID(html, name string) (string, bool) {
	for _, m := range siteLink.FindAllStringSubmatch(html, -1) {
		if m[2] == name {
			return m[1], true
		}
	}
	return "", false
}

// Import uploads site to POST /Dashboard/Import and returns the new site's
// ID, read from the dashboard's site list by name.
func (r *Run) Import(site Site) (string, error) {
	raw, err := json.Marshal([]Site{site})
	if err != nil {
		return "", err
	}
	resp, err := r.page.Request().Post(r.OAuchURL+"/Dashboard/Import", playwright.APIRequestContextPostOptions{
		Multipart: map[string]any{"file": playwright.InputFile{Name: "site.json", MimeType: "application/json", Buffer: raw}},
	})
	if err != nil {
		return "", fmt.Errorf("import site: %w", err)
	}
	if resp.Status() >= 400 {
		return "", fmt.Errorf("import site: OAuch answered %d", resp.Status())
	}
	if _, err := r.page.Goto(r.OAuchURL + "/Dashboard"); err != nil {
		return "", err
	}
	html, err := r.page.Content()
	if err != nil {
		return "", err
	}
	if id, ok := siteID(html, site.Name); ok {
		return id, nil
	}
	return "", fmt.Errorf("imported site %q isn't on OAuch's dashboard", site.Name)
}

// RunTests starts the test set for siteID and drives its popups until
// OAuch shows the results.
func (r *Run) RunTests(siteID string, timeout time.Duration) error {
	if _, err := r.page.Goto(r.OAuchURL + "/Dashboard/RunTest/" + siteID); err != nil {
		return err
	}
	if err := r.page.Locator(`button:has-text("Run test set")`).Click(); err != nil {
		return fmt.Errorf("start the test set: %w", err)
	}
	return r.drive(timeout)
}

var (
	resumeLink = regexp.MustCompile(`/Dashboard/Resume/([0-9a-f-]{36})`)
	resultsURL = regexp.MustCompile(`/Dashboard/Results/`)
	spaces     = regexp.MustCompile(`\s+`)
)

// Resume finishes the timed tests: it waits until until, then opens the
// latest run's resume page and drives it to the results. OAuch ignores a
// resume before a test's ResumeWhen, so the wait is required.
func (r *Run) Resume(siteID string, until time.Time, timeout time.Duration) error {
	if _, err := r.page.Goto(r.OAuchURL + "/Dashboard/Results/" + siteID); err != nil {
		return err
	}
	html, err := r.page.Content()
	if err != nil {
		return err
	}
	m := resumeLink.FindStringSubmatch(html)
	if m == nil {
		return fmt.Errorf("OAuch's results page for %s has no resume link", siteID)
	}
	if wait := time.Until(until); wait > 0 {
		r.Logf("waiting %s for OAuch's timed tests (until %s)", wait.Round(time.Second), until.Format(time.TimeOnly))
		time.Sleep(wait)
	}
	if _, err := r.page.Goto(r.OAuchURL + "/Dashboard/Resume/" + m[1]); err != nil {
		return err
	}
	return r.drive(timeout)
}

// Export returns GET /Dashboard/ExportData/{siteID}.
func (r *Run) Export(siteID string) ([]byte, error) {
	resp, err := r.page.Request().Get(r.OAuchURL + "/Dashboard/ExportData/" + siteID)
	if err != nil {
		return nil, err
	}
	if resp.Status() != 200 {
		return nil, fmt.Errorf("export: OAuch answered %d", resp.Status())
	}
	return resp.Body()
}

// stallAfter is how long a popup may sit on a oneauth page that is neither
// the login form nor consent before the run presses "Stalled test". Such a
// page is an error oneauth showed instead of redirecting, which is the
// expected answer to several of OAuch's attacks, and OAuch waits for a
// callback that won't come.
const stallAfter = 3 * time.Second

// drive handles OAuch's popups until the main page reaches the results.
func (r *Run) drive(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	parked := map[string]time.Time{}
	for time.Now().Before(deadline) {
		if resultsURL.MatchString(r.page.URL()) {
			return nil
		}
		for _, p := range r.page.Context().Pages() {
			if p == r.page {
				continue
			}
			// Match the host, not the URL: OAuch's callback URLs carry
			// oneauth's issuer in their query string.
			u, err := url.Parse(p.URL())
			if err != nil || u.Host != r.ASHost {
				continue
			}
			r.handlePopup(p, parked)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("OAuch didn't finish within %s (main page at %s)", timeout, r.page.URL())
}

func (r *Run) handlePopup(p playwright.Page, parked map[string]time.Time) {
	if n, _ := p.Locator(`input[name=username]`).Count(); n > 0 {
		_ = p.Locator(`input[name=username]`).Fill(r.Username)
		_ = p.Locator(`input[name=password]`).Fill(r.Password)
		if err := p.Locator(`form[action="/auth/login"] button[type=submit]`).Click(); err == nil {
			r.Logf("popup: logged in")
		}
		return
	}
	if n, _ := p.Locator(`button[name=action][value=approve]`).Count(); n > 0 {
		if err := p.Locator(`button[name=action][value=approve]`).Click(); err == nil {
			r.Logf("popup: approved consent")
		}
		return
	}
	key := p.URL()
	since, ok := parked[key]
	if !ok {
		parked[key] = time.Now()
		return
	}
	if time.Since(since) < stallAfter {
		return
	}
	stalled := r.page.Locator(`#stalledButton:not([disabled])`)
	if n, _ := stalled.Count(); n == 0 {
		return
	}
	title, _ := p.Locator("body").InnerText()
	if len(title) > 100 {
		title = title[:100]
	}
	if err := stalled.Click(); err == nil {
		r.Logf("popup: pressed Stalled test on %q", spaces.ReplaceAllString(title, " "))
		delete(parked, key)
	}
}
