# Testing and acceptance gates

## Required local/CI baseline

Run:

```bash
npm run typecheck
npm run eval:provenance
npm run eval:methodology
npm run build
node bin/skillmoo.mjs --version
node bin/skillmoo.mjs scan --dir examples/demo-skills --no-share
```

The demo scan intentionally contains an unsafe Skill and should exit `2`; that exit code is the passing CI-gate behavior.

## Change-specific requirements

- Detection or safety change: add a true-positive regression and a neighboring false-positive guard; run the private adversarial suite before synchronization/release.
- Score/rubric change: update rubric version when required, methodology, vector expectations, provenance, changelog, and package version decision.
- Optimizer change: prove verify-or-reject, protected code preservation, no new risk, no grade/gate regression, and read-only file behavior.
- CLI argument/output change: test human output, JSON contract, invalid input, exit codes, and the bundled binary.
- Shared engine change: run both repositories' affected suites and verify the intended source parity without copying private assets.
- Documentation-only change: run methodology/provenance when rating or evidence claims are touched; otherwise use Markdown/diff checks.

Report exact commands, results, expected non-zero exits, skipped private/external checks, and remaining risk.
