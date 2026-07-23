# How SkillMOO rates a skill

An independent rating is only worth something if you can **check it**. This is the
method. The engine that implements it is in [`../src/lib/`](../src/lib/) — nothing here
is a black box.

## The three computed dimensions (no model)

A grade is computed by static analysis of the `SKILL.md` text and any bundled scripts —
never by opinion, never by an LLM.

### 🛡 Safety
We read the skill and its scripts and look for **behavior that is actually dangerous**,
not just powerful:

- secret → sink **exfiltration** (a credential value concatenated into a URL / request
  body / known exfil host), reverse shells, `curl | sh`, decode-then-run;
- **persistence backdoors** (shell rc, crontab, git hooks, `authorized_keys`, MCP config);
- **prompt-injection** and forged system/role control tokens;
- destructive commands (`rm -rf /`, `~`, `$HOME`).

**Capability ≠ intent.** Static analysis can see what a skill *can* do (read `API_KEY`,
call the network, run a subprocess) — not *why*. A legitimate API/deploy client that
reads a key and calls its endpoint is **`review`** (disclosed capability), **never a
false `block`**. A `block` requires a real malice signal from the list above.

### 💨 Token cost
How many tokens the skill spends on **every single call** (it's loaded into context each
time it triggers), compared to the median. Bloated skills quietly tax every request.

### ⚠ Conflicts
Two skills whose **triggers overlap** (measured by Jaccard similarity of their trigger
surfaces) make the agent fire the wrong one. We flag the overlapping pairs so you can
narrow one.

## The grade is a reproducible score vector

The overall 0–100 score is a fixed weighting of per-axis subscores:

```
overall = structure·0.18 + trigger·0.24 + tokens·0.18 + risk·0.40
```

Each grade ships with its subscores + weights + a rubric version string, so **anyone can
re-derive the letter grade** from the vector. The weights and cutoffs are the single
source of truth in the engine — not a hidden model.

## The honesty rules (non-negotiable)

- **Efficacy / usefulness must be measured**, on a named model + task suite, or it isn't
  claimed. "Not yet tested" is an honest state; refusing to certify is a feature.
- **Ratings are never for sale.** The score is never influenced by payment; monetization
  is on the *fix* and *team* features, never the grade.
- **Two-sided accuracy.** The bar is: catch every real threat **and** never false-accuse a
  good skill. On 68 real official skills (Anthropic / Cloudflare / obra) the engine
  produces **0 false blocks** — the public credibility test.

## Optimize is verify-or-reject

The one-click optimize re-analyzes its **own** rewrite and only applies it if every
invariant holds — grade not lower, safety gate not worse, no new risk category, every
fenced code block byte-identical, name preserved. Otherwise it reverts to the original.
A one-click optimize can **never make a skill worse**.
