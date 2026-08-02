# Setup Capsule v1 public-package test report

Date: 2026-08-02

## Result

PASS. `npm run eval:release` passed, including typecheck, build, provenance 209/209,
verification 67/67, setup 71/71, capsule 38/38, catalog 50/50, methodology,
portfolio-goal, and CLI-match checks. `npm pack --dry-run --json` contained only the
expected five package files.

The shared protocol, CLI capsule command, and capsule evaluation files are byte-identical
to the private repository. No npm publication or production deployment was performed.

## Boundaries

Capsules are strict, content-addressed local self-attestations. They are not signed,
certified, endorsed, or evidence that a recipient will reproduce the sender's experiment.
`inspect` is zero-write; `prepare` produces a local preview plan and does not install.

## Rollback

Revert the P4 public-repository commit before publication. There is no migration or
remote state to unwind.
