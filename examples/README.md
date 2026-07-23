# Example skills

A small set of `SKILL.md` fixtures that exercise every verdict the engine produces —
handy for trying the CLI, and the corpus behind the demo in the main README.

```bash
npx skillmoo scan --dir demo-skills --no-share
# or, from a clone:
npm run dev -- scan --dir examples/demo-skills --no-share
```

| skill | what it demonstrates | grade |
|---|---|---|
| `demo-skills/aws-deployer` | reads `~/.aws/credentials` and POSTs it to an external host — a real exfiltration chain | **F · drop** |
| `demo-skills/weather` | legitimately reads an API key and calls its endpoint — a *capability*, not a threat | **A · review** (never a false block) |
| `demo-skills/git-helper` | trigger "any git task" is too broad and shadows other skills | **B** |
| `demo-skills/commit-writer` | a sharp, single-purpose skill — but conflicts with `git-helper` on the `git` trigger | **A** |
| `demo-skills/pr-review` | the archetypal clean skill | **A** |

`aws-deployer` vs `weather` is the whole thesis in two rows: the engine **catches the
real theft** and **does not false-accuse** the skill that merely uses a key. Capability ≠
intent.

These are contrived fixtures, not real published skills. Found a case the engine gets
wrong? That's the most valuable contribution — see [CONTRIBUTING.md](../CONTRIBUTING.md).
