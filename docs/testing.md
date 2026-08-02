# Testing and acceptance gates

## Required local/CI baseline

Run on Node 18.19.0 and Node 22:

```bash
npm ci
npm run eval:release
node bin/skillmoo.mjs --version
node bin/skillmoo.mjs scan --dir examples/demo-skills --no-share
npm pack --dry-run
```

The demo scan intentionally contains an unsafe Skill and should exit `2`; that exit code is the passing CI-gate behavior.

## Change-specific requirements

- Detection or safety change: add a true-positive regression and a neighboring false-positive guard; run the private adversarial suite before synchronization/release.
- Score/rubric change: update rubric version when required, methodology, vector expectations, provenance, changelog, and package version decision.
- Optimizer change: prove verify-or-reject, protected code preservation, no new risk, no grade/gate regression, and read-only file behavior.
- CLI argument/output change: test human output, JSON contract, invalid input, exit codes, the bundled binary, and fail-closed behavior for capped discovery or incomplete bundles.
- Match/catalog change: test constraints, abstention, trust-gate exclusion, exact index/catalog parity, offline materialization, tamper resistance, and bundled-binary parity.
- Setup change: test prepare non-mutation, exact confirmation, complete-tree analysis, target/source drift, private modes, rollback, caught-failure compensation, simulated crash recovery, concurrency, and damaged-state refusal.
- Verification change: test suite validation, deterministic graders, all-regular-file identity (including binary assets), duplicate rejection, aggregate budgets, redirect refusal, transient-only retries, provider/timeouts, redaction, receipt integrity, simulation non-promotion, and summary handling.
- Shared engine change: run both repositories' affected suites and verify the intended source parity without copying private assets.
- Documentation-only change: run methodology/provenance when rating or evidence claims are touched; otherwise use Markdown/diff checks.

Report exact commands, results, expected non-zero exits, skipped private/external checks, and remaining risk.

For a release candidate, `npm run eval:release` is the minimum aggregate gate. Also run
`npm pack --dry-run` and inspect the file list; the catalog version guard must fail closed
if `package.json` and `catalog/v2/index.json` differ.
