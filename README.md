# SkillMOO — grade the AI agent skills you've installed

> Know which of your AI agent **skills** are unsafe, bloated, or conflicting — before you trust them.
> The "Consumer Reports / Rotten Tomatoes for `SKILL.md`." 100% local, no model, no signup.

[![npm](https://img.shields.io/npm/v/skillmoo?color=f4a159&label=npm)](https://www.npmjs.com/package/skillmoo)
[![CI](https://github.com/shawnc000/skillmoo/actions/workflows/ci.yml/badge.svg)](https://github.com/shawnc000/skillmoo/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-16b981)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D18-16b981)](package.json)
![local](https://img.shields.io/badge/100%25-local%20%C2%B7%20read--only-8b9096)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-f4a159)](CONTRIBUTING.md)

**→ [skillmoo.com](https://skillmoo.com)** · **[npm](https://www.npmjs.com/package/skillmoo)** · **[how we rate](docs/how-we-rate.md)**

```bash
npx skillmoo scan
```

<p align="center"><img src="assets/scan-demo.svg" alt="skillmoo scan grading five example skills — an F for a credential-exfiltration skill, an A·review for a legit key-using skill, and a trigger conflict" width="820"></p>

Agent skills (`SKILL.md` files for Claude Code, OpenAI Codex, Cursor, Copilot, Cline)
became software — but the controls didn't follow. You can't tell which of your skills
reads your keys, quietly burns tokens on every call, or fights another skill for the
same trigger. **SkillMOO grades every skill on safety, token cost, and conflicts** with
real, deterministic static analysis (no model, no signup) — and one-click-optimizes the
safe wins. It's **100% local and read-only**: it never edits your files, and never
uploads your file contents.

## What one scan catches

The demo above is [five real example skills](examples/) — and it's the whole thesis in
one screen:

- **🛑 It catches the real theft.** `aws-deployer` reads `~/.aws/credentials` and POSTs
  it to an external host → **F, drop**. That's an exfiltration chain, not a lint nit.
- **🟢 It doesn't false-accuse.** `weather` also reads a key and calls the network — but
  legitimately → **A, review**, never a false "block." **Capability ≠ intent** is the
  hard part every naive scanner gets wrong, and the reason you can trust the F above.
- **⚠️ It sees across skills.** `git-helper`'s "any git task" trigger *shadows*
  `commit-writer` — the top cause of an agent firing the wrong skill.

Reproduce it yourself: `npx skillmoo scan --dir examples/demo-skills --no-share`.

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
