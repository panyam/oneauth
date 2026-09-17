---
name: capture-the-artifact-not-the-substring
description: "Capturing real output for a PR's before/after section catches serialization bugs that substring assertions miss. Lesson from the DPoP `WWW-Authenticate` comma bug (#336, PR 372)."
metadata:
  node_type: memory
  type: feedback
---

When a change emits a serialized wire format (an HTTP header, a JSON body, a JWT), assert its **syntax**, not just that your content appears somewhere inside it. Substring assertions prove presence and say nothing about whether the result parses.

**Why:** Concrete case: PR 372 built `WWW-Authenticate: DPoP error="invalid_token" error_description="..." algs="..."` with space-separated parameters. RFC 9110 §11.6.1 requires commas (RFC 9449 Figure 16 shows the shape). All 17 middleware tests passed, because each asserted `assert.Contains(challenge, 'error="invalid_token"')` — true in both the correct and the broken rendering. A conforming client would have parsed the whole run as one malformed auth-param and discarded the error it was supposed to act on. The bug surfaced only when capturing the real header for the PR's before/after section, where the missing commas were visible at a glance.

**How to apply:**
- Treat the PR's **before/after capture as a verification step**, not documentation. Run the thing, paste the bytes, read them. It exercises a different sense than the assertions do.
- For any header or encoded field, assert at least one test on the **separator and ordering**, e.g. `assert.Regexp(t, 'error_description="[^"]*", algs="', challenge)`, so the grammar is pinned and not just the vocabulary.
- Capture the "before" column by actually running the parent commit (a throwaway `git worktree add /tmp/x HEAD~1` plus a scratch test), rather than describing it from reading the old code. Twice this session the captured output differed in detail from what the code read like.
- The same trap shows up wherever the encoding layer is more forgiving than the spec: see [[feedback_encoding_layer_normalization]] for the base64 variant.

See also: [[feedback_pr_docs]] for keeping the PR body part of the work rather than an afterthought.
