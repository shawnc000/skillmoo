# Setup Capsule v1 public-package handoff

The public CLI now supports deterministic `capsule create`, zero-write `capsule inspect`,
and preview-only `capsule prepare`. Its shared protocol, CLI implementation, and
adversarial evaluation remain byte-identical to the private product repository.

The public branch is the reviewable protocol and CLI distribution boundary. Production
Web activation, npm publication, hosted receipt exchange, authentication, persistence,
and analytics are intentionally outside this change.

See `spec.md`, `design.md`, the ADR, and `test-report.md` for the contract, trust boundary,
decision rationale, validation, and rollback.
