---
name: unrendered-is-unvalidated
description: "A format nothing renders is a format nothing validates. Check the consumer exists before improving the content. Lesson from the docs site never loading mermaid (PR 383)."
metadata:
  node_type: memory
  type: feedback
---

Before improving content in a rendered format, check that something actually renders it. If nothing does, the content has never been validated either, and improving it is the second job rather than the first.

**Why:** Concrete case: the OneAuth docs site served every ```mermaid fence as `<pre class="language-mermaid">`, its own source text. Eight sequence diagrams in `AUTH_FLOWS.md` had never rendered for anyone, on the live site or locally. The task as asked was "convert the ASCII diagrams to mermaid", and doing that alone would have been a regression: ugly-but-readable box drawings replaced by raw `sequenceDiagram` source. Worse, three existing fences did not parse (a bare `"` in a sequence message, and `;` in two notes, each of which truncates a statement). Those would have become error boxes the moment a renderer landed, and two had been broken for months. Nobody noticed because nothing ever tried.

**How to apply:**
- When asked to improve content in a rendered format (mermaid, LaTeX, a diagram DSL, a template language), grep the consumer first: is a renderer wired, and does the built output actually contain it? `grep -c 'language-mermaid'` on the built page answers it in seconds.
- If the renderer is missing, it is the prerequisite rather than a follow-up. Land it in the same change as the content, or the content change is a downgrade.
- Then validate every block with the real parser rather than by eye. For mermaid that is `mermaid.parse` under jsdom. Eyeballing missed three broken blocks a parser found instantly.
- The general shape: content in an unrendered format is an unexercised code path, and unexercised paths rot. See [[feedback_capture_the_artifact]] for the same idea applied to wire formats, and [[feedback_red_check_each_test]] for it applied to tests.
