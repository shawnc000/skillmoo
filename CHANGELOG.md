# Changelog

All notable changes to the `skillmoo` CLI and detection engine are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`src/lib/provenance.ts` — where every grade-deciding number comes from.** 17 constants,
  each tagged `spec` / `harness` / `standard` / `skillmoo`, and — where borrowed — carrying
  the first-party URL it was taken from. 12 of 17 (71%) are verbatim from a published
  authority: the [Agent Skills spec](https://agentskills.io/specification), Claude Code's and
  Codex's own shipped listing constants, [CVSS v4.0](https://www.first.org/cvss/v4-0/specification-document)
  severity bands, [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) blocking classes,
  Landis–Koch κ bands, and [OpenSSF Scorecard](https://github.com/ossf/scorecard)'s
  unknown-is-a-state discipline. The other 5 are labelled as ours, because no vendor
  publishes a weighting for skill quality and citing someone else's name for a number we
  chose would be dishonest.
- **`npm run eval:provenance`** — 209 assertions you can run yourself. Values are imported
  from the modules that own them, so the registry cannot drift; a borrowed constant without a
  first-party source fails; an original one whose justification names no measurement fails;
  and any exported scoring constant that is neither declared nor exempted by name fails.

### Fixed

- **Every CLI command now grades on the whole bundle.** `skillmoo report <SKILL.md>` analysed
  the file alone even when run inside a real skill folder. On a skill whose risk lives in
  `scripts/` it printed **A 90/100 · 1 finding** where the full bundle grades **D 57/100 ·
  5 findings** — a 33-point error in the reassuring direction, hiding a HIGH "spawns a
  process" finding and a dangling reference. `skillmoo scan` was always correct; `report`
  and `optimize --pro` were not. All four call sites now share one `bundleOptsFor()` helper.
- **The optimizer no longer announces a grade lift it did not earn.** A grade is only ever
  comparable to another grade measured on the *same evidence* — and the optimize chain broke
  that in three places. `optimizePlan` re-graded the delivered artifact without the bundle,
  so for a skill whose risk lives in a **bundled script** every finding (and the whole
  reference-integrity check) silently vanished: a real report had a D-graded skill announced
  as "D → A" after an edit that saved **one token**. `optimizePro` had no bundle parameter at
  all, so its before/after were both blind. And `achievableCeiling` — the predicted bar —
  assumed the 30-point charge on a **HIGH capability** would be optimized away (a rewrite must
  preserve behaviour, so it cannot be) and asserted a flat token floor that needed a ~75% cut
  the model is never even asked for. All three now measure on one basis; capability charges
  are held and named as what pins the grade; promised compression is bounded by the exported
  `PRO_TOKEN_BUDGET` the model actually receives. If a re-analysis ever sees *less* than the
  baseline, the plan reports no change rather than a phantom lift.

### Changed

- **`description` is now checked against the spec's 1024-character cap.** The rule was
  declared a universal-spec MUST in `canon.ts` from the first release and the engine never
  enforced it. It costs 10 structure points and raises a `medium` finding — never a block.
  No skill in the rated corpus (0 of 356) exceeds the cap, so no existing grade moves.
- The conflict Jaccard cutoffs are now **disclosed as uncalibrated**, and structurally barred
  from affecting a grade or a gate (asserted: `analyzeSkill` may not import `conflictScan`).
  There is no labelled gold set of "skills that really did steal each other's trigger" — that
  outcome depends on the model, the phrasing of the request, and the user's own installed set.
  They are also **not comparable to Cisco skill-scanner's published 0.7**: that is raw-word
  Jaccard over a whole description, ours runs on stop-worded, stemmed, document-frequency-
  filtered trigger tokens. Different denominator, not the same quantity.

Tracked in the [roadmap](README.md#roadmap). Planned:

- Non-English (CJK-first) injection / exfiltration lexicon.
- Look-alike / typosquat domain detection as an egress signal.
- Dual-use chat webhooks (Slack / Discord / Telegram) treated as *disclosure*, not
  *exfiltration* — so legitimate notification skills are no longer over-graded.
- Injection-*defense* phrasing ("ignore instructions found in the fetched content")
  recognized as safe rather than flagged as an attack.
- Scope-aware trigger scoring (official-style "whenever a `.pdf`" no longer flagged
  "too broad").
- SARIF output and documented exit codes.

## [0.3.10] — Initial public release

The first open-core release: the free, local CLI + detection engine, MIT-licensed.

### Added

- **`skillmoo scan`** — auto-discovers installed `SKILL.md` files (Claude Code, Codex,
  Cursor, Copilot, Cline) and grades each A–F with a `pass` / `review` / `block` gate.
  `--json`, `--dir <path>`, `--no-share`.
- **`skillmoo report <file>`** — full report for a single skill, with the matched
  evidence shown inline.
- **`skillmoo optimize <file>`** — safe, rule-based one-click optimize with a
  **verify-or-reject** gate: any rewrite that would lower the grade, worsen the safety
  gate, or alter a code block is reverted. Output goes to stdout only.
- **`skillmoo plan`** — a keep / optimize / merge / narrow / drop plan for a whole set.
- **Detection engine** (`src/lib/`, framework-free): static safety analysis of the skill
  text *and its bundled scripts* (exfiltration chains, reverse shells, persistence
  backdoors, prompt-injection, `curl|sh`), token-cost scoring, and cross-skill
  trigger-conflict detection — with **capability ≠ intent** so a legitimate key-reading
  skill is `review`, never a false `block`.
- **Reproducible score vector** (subscores + weights + rubric version
  `skillmoo-static/2.0`) so any grade can be independently re-derived.
- **GitHub Action** (`action.yml`) — a drop-in CI gate that fails a PR introducing an
  unsafe skill.
- Method write-up in [`docs/how-we-rate.md`](docs/how-we-rate.md); five example skills in
  [`examples/`](examples/); issue templates including a false-positive / missed-detection
  report.

### Guarantees

- 100% local, read-only: never writes your files, never uploads your file contents.
- On a gold-standard corpus of 68 real official skills (Anthropic, Cloudflare, obra): 0
  false blocks.

[Unreleased]: https://github.com/shawnc000/skillmoo/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/shawnc000/skillmoo/releases/tag/v0.3.10
