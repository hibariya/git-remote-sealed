# Format reorganization map

This is a documentation-only move from commit `9fc1441bfa65`.
Rules, section numbers, examples, and recovery commands retain their wording.
The map lets reviewers compare the old document with the new locations.

| Original location in FORMAT.md | New location |
| --- | --- |
| Introduction and §§1–10, excluding the notes listed below | Same sections in [FORMAT.md](FORMAT.md) |
| Notes 7d and 7h, including the migration requirements | Still in [FORMAT.md §7.4](FORMAT.md#74-trust-on-first-use-and-the-per-vault-memory) |
| Appendix A, including every recovery command | Still in [FORMAT.md](FORMAT.md#appendix-a-disaster-recovery-with-stock-tools) |
| Appendix B version history | [Design notes, Appendix B](DESIGN-NOTES.md#appendix-b-version-history); original heading retained as a pointer |
| Notes 3a, 3b, 3c (§3) | [Design notes for §3](DESIGN-NOTES.md#section-3) |
| Notes 4a, 4b (§4.1) | [Design notes for §4.1](DESIGN-NOTES.md#section-4-1) |
| Notes 4c, 4d (§4.3) | [Design notes for §4.3](DESIGN-NOTES.md#section-4-3) |
| Notes 5a (§5) | [Design notes for §5](DESIGN-NOTES.md#section-5) |
| Notes 6a (§6) | [Design notes for §6](DESIGN-NOTES.md#section-6) |
| Notes 7a, 7b, 7c (§7.3) | [Design notes for §7.3](DESIGN-NOTES.md#section-7-3) |
| Notes 7e, 7f, 7g (§7.4) | [Design notes for §7.4](DESIGN-NOTES.md#section-7-4) |
| Notes 8a, 8b, 8c, 8d, 8e (§8) | [Design notes for §8](DESIGN-NOTES.md#section-8) |
| Notes 9a (§9) | [Design notes for §9](DESIGN-NOTES.md#section-9) |

## Meaning checks

The move was checked against the baseline above: after removing the explicit
navigation additions, every retained byte matches the original. Each moved
note and the complete version-history body also match the original exactly.
The new reference links resolve the existing `[3a]`-style note markers.

Notes 7d and 7h were kept in the reference despite being under a heading
calling them background: they contain MUST/SHOULD language. Security limits,
exceptions, and the authority split remain in the reference; the background
notes supplement them. No ambiguity was resolved by rewriting a rule.

## New explanatory material

The separately added [overview](OVERVIEW.md) summarizes §§3–9 and points
to §10 for security limits. It explicitly defers to FORMAT.md and its
existing authority split with the model. README.md and the reference's
introduction link to it; no existing rule wording was rewritten.
