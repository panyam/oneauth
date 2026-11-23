# tests/oauch

`make testoauch` runs OAuch against oneauth-server through OAuch's dashboard with playwright-go, and checks the results against `expected.yaml` (issue 567). `docs/conformance/oauch.md` has the triage for every entry.

- **Updating `expected.yaml`.** A run logs `now passes, remove from expected.yaml: X` for a listed test that passed. An unlisted test that doesn't pass fails the run. Add it only with a verdict from `oauch.md`, and add a row there too. `test-reports/oauch/oauch-export.json` holds the run's full results and logs.
- **Popups match on the host.** OAuch's callback URLs carry oneauth's issuer in their query string, so matching on the URL text presses "Stalled test" on callbacks that are still loading and cuts tests short.
- **OAuch ignores a resume before a timed test's `ResumeWhen`**, about 12 to 15 minutes after the first pass. `Run.Resume` waits for it, so a run takes about 15 minutes.
- **`localhost.emobix.co.uk` must map to the host's IPv4 address inside OAuch's container.** oneauth-server listens on IPv4 only. `make upoauch` resolves `host.docker.internal`, or falls back to the bridge gateway.
- **The site JSON uses OAuch's field names** (`SiteSettings` in OAuch.Shared). A renamed key imports as OAuch's default, and `TestNewSite_UsesOAuchFieldNames` pins them.
- **playwright-go publishes as `github.com/mxschmitt/playwright-go`** from v0.6201 on. `make oauch-browser` installs its driver and Chromium, and `scripts/exercise-oauch.sh` does it too.
- **Bumping OAuch:** change `OAUCH_REF` in the Makefile, `rm -rf tests/oauch/.oauch`, run once, and update `expected.yaml` from what the run reports.
