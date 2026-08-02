# Changelog

All notable changes to the `skillmoo` CLI and detection engine are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Goal-based trusted matching shared by CLI and Web.** `skillmoo match "<goal>"` and
  `skillmoo plan --goal "<goal>"` use the same deterministic bilingual retrieval and
  combination planner. Automatic candidates are limited to A/B, safety-gate PASS,
  low-risk Skills; exclusions are preserved; combinations are capped and never padded;
  unsupported goals abstain. Output separates per-Skill inspection from the untested
  exact combination instead of implying runtime success.
- **Environment-scoped paired verification.** `skillmoo verify` runs objective JSON task
  suites against declared current/proposed ordered setups with shared seeds and model
  settings. Egress requires `--send-to-model`; simulations cannot become verified
  evidence; private append-only receipts omit prompts, outputs, Skill contents, and
  credentials and remain explicitly local self-attestations.
- **Transactional complete-package setup.** `skillmoo setup` separates no-mutation
  prepare from exact-ID-confirmed apply, analyzes the complete directory, executes no
  package code, rechecks source/target drift, compensates caught failures, and provides
  idempotent rollback plus explicit crash recovery without guessing.
- **Pinned offline artifact pilot.** `skillmoo catalog` embeds four complete MIT Skill
  packages bound to one immutable upstream repository commit. Exact bytes, Git blob
  identities, license evidence, full-bundle assessment, immutable cache state, and the
  exact CLI package version are validated before setup planning. The catalog covers all
  115 match entries with reason-coded non-embedded states; a complete-package gate
  failure is excluded from automatic matching.
- **Independent release gates** for matching, portfolio planning, verification, setup,
  and Catalog v2, including invalid options, tamper, offline, concurrency, recovery, and
  bundled-binary parity checks. `npm run eval:release` runs the aggregate public gate.

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

### Security

- Hosted scan reports are minimized to anonymous ordinal labels and derived verdicts;
  names, paths, details, evidence snippets, raw content, and optimization changes stay local.
- Discovery rejects symbolic-link escapes and oversized entry points; terminal output strips
  control, bidi, and invisible tag sequences from untrusted labels.
- Verification binds binary and other regular assets into exact setup identity, rejects
  duplicate setups, refuses redirects and non-transient retries, and enforces aggregate
  request/input/output ceilings. Recovery refuses a live foreign transaction owner.
- CI runs the aggregate release gate, unsafe-scan smoke test, and package dry-run on
  Node 18.19.0 and Node 22.

### Fixed

- **The public rating formula now matches rubric 2.0.** `docs/how-we-rate.md` still
  published the removed 1.0 weighted-average formula even though the engine has used a
  subtractive risk penalty since 0.3.10. The method now names the live rubric, formula,
  grade cuts, and capability-vs-threat semantics. `npm run eval:methodology` imports the
  live constants and fails CI if those grade-deciding facts drift again. Documentation
  and verification only; no score or historical result changes.
- **The credential-exfiltration rule was firing only on legitimate code — 3 for 3.** Measured
  across 140 public skills from 9 repos (87 with a bundle): this `critical` rule produced 3
  findings and **all three were false positives** (3.4%, 95% CI 1.2–9.7%), with **zero true
  positives**. `anthropics/skills` **pptx** (`os.environ.copy()` handed to a subprocess, plus an
  AF_UNIX socket used to *detect* sandbox restrictions), `cloudflare/skills` (two **single-key**
  reads inside an f-string URL), `obra/superpowers` **brainstorming** (`process.env.X` config
  reads plus a `127.0.0.1` WebSocket) all graded **F / BLOCK**. It went unnoticed because the
  "official skills, zero false blocks" benign arm analysed SKILL.md **without bundles**, so the
  rule was never exercised against bundled scripts.

  Five mechanisms, each traced to a line: a tainted name matching inside a **quoted literal**; a
  tainted name matching in a **property position** (`.env.` inside `process.env.KEY` silently
  defeated the rule's own single-key exclusion); `===` parsed as an assignment; the 80-char RHS
  cap **severing** an expression and manufacturing a whole-env read; and the sink-argument
  extractor **scavenging forward past end-of-line** onto an unrelated call. Plus, in
  `scriptScan`, only the *first* host in a bundle was kept — so one comment containing
  `127.0.0.1` disarmed the raw-IP check for everything after it.

  What was **rejected** matters more than what shipped: narrowing the sinks, reducing taint to
  direct aliasing, or confining taint per file each let genuine credential stealers fall from
  BLOCK to REVIEW (13 measured escapes), and a naive literal scrubber let the three most
  idiomatic whole-env reads escape — `subprocess.check_output("printenv")`,
  `open("/proc/self/environ")`, `execSync('printenv')`. `.send`/`.write`, multi-pass
  propagation and whole-bundle concatenation are all **kept**.

  Result on real bundles: critical exfil findings **3 → 0**; blocking skills **4 → 1**. Test
  coverage **294 → 316** for the three attack classes the suite could not see.
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
