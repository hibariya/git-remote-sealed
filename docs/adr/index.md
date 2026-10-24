# Architecture decision records

One file per decision: **what** we chose and **why**. They cover how this implementation works. The format itself is defined in [FORMAT.md](../FORMAT.md), and the reasons behind its rules are in [DESIGN-NOTES.md](../DESIGN-NOTES.md); a format change goes there, not here.

## Writing a new one

Add an ADR in the same change as the code it describes.

- File: `YYYY-MM-DD-short-slug.md`, dated the day the decision was made (a backfilled one gets its historical date). Add one line to the list below, newest first.
- Never rewrite an old ADR. To change a decision, write a new one and set the old one's Status to `Superseded by YYYY-MM-DD-slug` (or `Accepted (amended by YYYY-MM-DD-slug)` for a partial change).
- Every "why" needs a source: a doc, a commit, an issue, or a measurement. No source → "Rationale not recorded."
- Status: `Proposed` | `Accepted` | `Rejected` | `Deprecated` | `Superseded by YYYY-MM-DD-slug`.
- Short, easy English, about 15–40 lines:

```markdown
# <The decision as a statement>

- Status: Accepted
- Date: YYYY-MM-DD
- Sources: ...

## Context
Why we had to decide.
**Previously:** <only if this replaced an earlier choice>

## Decision
We ...

## Alternatives
- X: rejected because ... (or "None recorded.")

## Consequences
- Costs we accept, follow-ups, related ADRs.
```

## Decisions

(None yet.)
