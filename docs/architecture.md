# Architecture

## Scope

This public repository contains the auditable, local-first SkillMOO CLI and deterministic static engine. The hosted product lives in the private `skillmoo-web` repository and adds Web UI, catalog pages, auth, billing, hosted reports, private evaluation data, and model-backed Pro features.

## Components

- `cli/`: command parsing, installed-Skill discovery, terminal and HTML reporting.
- `src/lib/`: framework-free analysis, safety, token, conflict, provenance, portfolio, and verify-or-reject optimization logic.
- `scripts/build-cli.mjs`: bundles the CLI and engine into the dependency-free `bin/skillmoo.mjs` npm artifact.
- `scripts/eval-provenance.ts`: verifies source attribution and evidence integrity.
- `scripts/eval-methodology.ts`: keeps the published method aligned with executable rubric constants.
- `examples/`: deterministic smoke-test fixtures.

## Runtime flow

```text
installed or supplied Skill bundle
  -> local discovery and bounded file reads
  -> deterministic analysis
  -> per-Skill grade/gate/findings + portfolio conflicts
  -> optional verify-or-reject rewrite printed as output
```

The CLI is local and read-only with respect to user Skill files. Any reporting network behavior must be explicit, content-minimized, and documented by the command.

## Cross-repository rule

Shared engine changes are copied deliberately between public and private repositories. Do not copy private gold labels, efficacy tasks, strategy, credentials, hosted integrations, or account/billing code into this repository. A release must record which private and public commits correspond to the npm artifact.
