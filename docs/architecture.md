# Architecture

## Scope

This public repository contains the auditable, local-first SkillMOO CLI and deterministic static engine. The hosted product lives in the private `skillmoo-web` repository and adds Web UI, catalog pages, auth, billing, hosted reports, private evaluation data, and model-backed Pro features.

## Components

- `cli/`: command parsing, installed-Skill discovery, terminal/HTML reporting, paired verification, transactional setup, and offline catalog materialization.
- `src/lib/`: framework-free analysis, safety, token, conflict, provenance, portfolio, trust/evidence, goal matching, and verify-or-reject logic.
- `src/data/matchCatalog.ts`: compact audited A/B · PASS · low-risk retrieval catalog shared with the hosted Web product.
- `catalog/v2/`: exact-version artifact index, upstream source lock, notices, and four reviewed complete-package payloads.
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
  -> optional goal match / portfolio plan
  -> optional no-mutation setup plan
  -> explicitly confirmed transactional apply + local receipt
  -> optional explicitly approved paired environment verification
```

Static analysis, matching, catalog materialization, and setup preparation are local.
Scanning never edits user Skill files. Setup mutation requires an exact plan identity and
supports rollback/recovery; no Skill code is executed. Network egress is limited to
explicit `scan --publish`, `optimize --pro`, or `verify --send-to-model` paths and must be
documented by the command. Hosted scan payloads use ordinal labels and derived verdicts
only; verify refuses redirects, binds every regular package file into setup identity, and
enforces aggregate request/input/output budgets.

## Cross-repository rule

Shared engine and generated trust artifacts are copied deliberately between public and
private repositories. Public source may contain the compact match catalog and approved
redistributable artifact payloads, but not private gold labels, efficacy answer keys,
credentials, hosted integrations, account/billing code, or internal strategy. A release
must record which private and public commits correspond to the npm artifact.
