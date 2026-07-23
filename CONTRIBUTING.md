# Contributing to SkillMOO

Thanks for helping make agent-skill ratings more accurate. SkillMOO is maintained by a
solo developer, so a little structure keeps things sane.

## What's most welcome

- **Detection rules** — a real attack pattern the engine misses, or a false positive it
  shouldn't raise. Open an issue with a minimal `SKILL.md` that reproduces it. This is
  the highest-value contribution: every real example makes the engine sharper.
- **Bug fixes** in the CLI or engine (`cli/*`, `src/lib/*`).
- **Docs / examples** — clearer explanations, more real-world sample skills.

## How ratings stay trustworthy

To keep SkillMOO a *credible independent authority*, a few things are deliberately **not**
open to change by PR, and live in the hosted product instead:

- **The calibration gold set and efficacy measurements** — the "answer key" is curated
  internally and multi-rater reviewed; a public, editable answer key would be gameable.
- **The exact adversarial test suite** — same reason (a public exam gets memorized).

So a detection-rule change is evaluated against that private regression before it ships.
Propose the *behavior* (with a reproducing example); the maintainer runs it through the
gate. If it catches a real threat without false-accusing good skills, it lands.

## Ground rules (the honesty pledge, in code)

Any change must keep these true — they're the whole product:

1. **Capability ≠ intent.** A skill that *can* read a key / call the network / run shell
   is `review`, not a false `block`. A `block` needs a real malice signal (secret→sink
   exfil, obfuscation, injection, `curl|sh`, reverse shell, persistence backdoor).
2. **No invented efficacy.** Never claim a skill "works better" without a measurement.
3. **Optimize is verify-or-reject.** An optimize that could lower the grade, add a risk
   category, or alter a code block must revert. It can never make a skill worse.
4. **The CLI is read-only.** `scan` / `report` / `optimize` never write the user's files
   and never upload file contents.

## Dev setup

```bash
npm install
npm run dev -- scan --dir ./examples   # run the TypeScript CLI
npm run typecheck
npm run build                          # esbuild → bin/skillmoo.mjs
```

By contributing you agree your contribution is licensed under the repo's [MIT License](LICENSE).
