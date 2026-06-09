---
name: spec-inheritance-comparison-semantics
description: "When an RFC inherits comparison semantics from another RFC, look at the inherited spec's primitive — don't guess based on the data type. Lesson from `client.ValidateIss` (#246)."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 6fb74608-8281-4b59-b971-f0082070b51b
---

When implementing a comparison or validation primitive that an RFC defines by *reference* to another RFC, the inherited spec is the source of truth — not your intuition about what the data looks like.

**Why:** Concrete case: RFC 9207 §2.4 says the `iss` query parameter is validated "in the same way as defined for the iss claim in [RFC 9068]." RFC 9068 §2.1.1 (JWT iss claim) is **byte-equal** — no normalization. We initially implemented `client.ValidateIss` with RFC 3986 §6.2 URL normalization (scheme + host lowercase, trailing-slash strip) because *it looks like a URL*. The MCP `auth/iss-normalized` conformance scenario tests exactly this trap: any normalization fails. mcpkit shipped its own validator rather than use ours, because using ours would regress its conformance score. We then had to flip 7 existing test assertions from accept to reject. Issue #246, fixed after v0.1.21.

**How to apply:**
- When the spec says "compare X the same way as Y," **find Y's primitive and link to it from the doc comment**. Don't paraphrase, don't infer.
- Default to byte-equal until the spec explicitly invokes a named normalization (RFC 3986 §6.2, NFC, etc.).
- If a conformance suite exists (MCP, OIDF, FAPI), check its grading rubric for the validator *before* picking a comparison primitive. The rubric is the ground truth that downstream consumers will be measured against.
- Cite both specs and the conformance scenario in the validator's doc comment so a future reader doesn't re-derive (and re-bug) the rule.

See also: [[feedback_pr_docs]] for the doc-comment hygiene that makes this future-proof.
