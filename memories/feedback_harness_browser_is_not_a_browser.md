---
name: harness-browser-is-not-a-browser
description: "A conformance harness's scripted browser ignores CSP and COOP, so a green OIDF run says nothing about real browsers. Run a browser flow in real Chrome before trusting it. Lesson from the OAuch run (issue 497)."
metadata:
  node_type: memory
  type: feedback
---

The OIDF plans passed for months while no real browser could finish an authorization with oneauth-server. The CSP's `form-action 'self'` blocked the consent and login forms' redirect back to the client, and `Cross-Origin-Opener-Policy: same-origin` cut popup logins off from their opener. The harness drives HtmlUnit, which enforces neither header; the Go tests use HTTP clients. Only the OAuch run, in real Chrome, found it.

**Why:** a test browser that skips a browser's security model makes header bugs invisible, however many modules pass.

**How to apply:** when a change touches security headers, redirects or pages a user clicks through, drive the flow once in real Chrome (the Playwright tools, or OAuch) and watch the console for CSP and COOP errors. Related: [[live-test-corrects-fakes]], [[unrendered-is-unvalidated]].
