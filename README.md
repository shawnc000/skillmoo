# SkillMOO — grade the AI agent skills you've installed

> Know which of your AI agent **skills** are unsafe, bloated, or conflicting — before you trust them.
> The "Consumer Reports / Rotten Tomatoes for `SKILL.md`." 100% local, no model, no signup.

**→ [skillmoo.com](https://skillmoo.com)** · **[npm](https://www.npmjs.com/package/skillmoo)** · **[how we rate](docs/how-we-rate.md)**

Agent skills (`SKILL.md` files for Claude Code, OpenAI Codex, Cursor, Copilot, Cline)
became software — but the controls didn't follow. You can't tell which of your skills
reads your keys, quietly burns tokens on every call, or fights another skill for the
same trigger. **SkillMOO grades every skill on safety, token cost, and conflicts**
with real, deterministic static analysis — and one-click-optimizes the safe wins.

```bash
npx skillmoo scan
```

100% local: it finds every skill installed across Claude Code / Codex / Cursor /
Copilot / Cline, grades each (safety · bloat · conflicts), and prints a report.
**Read-only — it never edits your files, and never uploads your file contents.**

```
  drop    aws-helper          F   reads ~/.aws/credentials + network egress → likely exfiltration
  narrow  git-helper          B   trigger "any git task" shadows 3 other skills
  keep    pr-review           A   lean, sharp trigger, no risky behavior
  ────────────────────────────────────────────────────────────────────────
  12 skills · 1 unsafe · 3 optimizable · 18,402 tokens/call total
```

## Commands

| Command | What it does |
|---|---|
| `skillmoo scan` | grade every installed skill · `--json` · `--dir <path>` · `--no-share` |
| `skillmoo report <file>` | full report for one `SKILL.md` |
| `skillmoo optimize <file>` | safe, rule-based one-click optimize (before → after, **verify-or-reject**) |
| `skillmoo plan` | a keep / optimize / merge / narrow / drop plan for your whole set |

Every optimize is **verified before it applies** — grade, safety gate, and code blocks
can only stay or improve. It can never make a skill worse.

## How it grades (no black box)

The whole point of an independent rating is that you can **audit it**. The engine is
right here in [`src/lib/`](src/lib/) and the method is written up in
[`docs/how-we-rate.md`](docs/how-we-rate.md). In short:

- **🛡 Safety** — static analysis of the skill text *and its bundled scripts*: real
  exfiltration chains, reverse shells, persistence backdoors, prompt-injection, `curl|sh`.
  **Capability ≠ intent:** a skill that legitimately reads a key and calls its API is
  *review*, never a false "exfiltration/block."
- **💨 Token cost** — how many tokens it spends on every single call vs the median.
- **⚠ Conflicts** — trigger-surface overlap that makes an agent fire the wrong skill.

Grades are a **reproducible score vector** (subscores + weights + rubric version), so
anyone can re-derive the A/B/C. On a corpus of **68 real official skills** (Anthropic,
Cloudflare, obra) the engine produces **0 false blocks** — the credibility test, run in
public at [skillmoo.com/how-we-rate](https://skillmoo.com/how-we-rate/).

## Badge

Show a skill's independent grade in its README (grab the exact snippet on any
[rated skill page](https://skillmoo.com/skill/)):

```md
[![SkillMOO](https://skillmoo.com/badge/wrangler)](https://skillmoo.com/skill/wrangler/)
```

## CI gate (GitHub Action)

Fail a PR that adds an unsafe `SKILL.md`:

```yaml
- uses: shawnc000/skillmoo@main
  with:
    dir: .claude/skills
```

## Develop

```bash
npm install
npm run dev -- scan --dir ./path/to/skills   # run the TS CLI directly
npm run build                                 # bundle → bin/skillmoo.mjs
```

The CLI is a thin shell over the framework-free engine in `src/lib/*` (no runtime deps;
esbuild inlines it into one file). See [CONTRIBUTING.md](CONTRIBUTING.md).

## What's here vs. hosted

This repo is the **free, local CLI + detection engine** — open so the rating is
auditable. The hosted service at [skillmoo.com](https://skillmoo.com) adds the rated
store, per-skill pages, measured-efficacy certification, and Pro model-optimize.
**Ratings are never for sale** — we monetize the *fix* and *teams*, never the score.

## License

[MIT](LICENSE) © SkillMOO
