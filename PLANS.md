# Complex implementation plans

Use this file for any complex or high-impact task classified by `AGENTS.md`. A plan is a decision record, not a ceremonial checklist: it must expose choices that could cause rework before code changes begin.

## Lifecycle

1. Inspect the smallest relevant code, tests, configuration, runtime constraints, and both-repository boundary.
2. Write the plan using the template below and mark it `Draft`.
3. Resolve zero to three genuinely blocking questions, with a recommended default.
4. Wait for explicit approval unless the current task already authorizes implementation without another confirmation.
5. Mark the plan `Approved`, implement it without silently changing design, and keep validation evidence current.
6. If a stop condition in `AGENTS.md` occurs, mark the plan `Blocked` and report the contradiction.
7. On completion, mark it `Complete` and add results, deviations, risks, and rollback instructions.

Valid statuses: `Draft`, `Approved`, `In progress`, `Blocked`, `Complete`, `Superseded`.

## Required plan template

```md
# <Feature or change name>

Status: Draft
Owner: <person or agent>
Last updated: YYYY-MM-DD
Task card: <link or short identifier>

## Goal and measurable acceptance criteria

## Blocking questions
<!-- Zero to three; include the recommended default. Write “None” when there are none. -->

## Assumptions
1. <specific and falsifiable>

## Impact map
- Repositories and files:
- Public API / compatibility:
- Data / schema / migration:
- Auth / security / privacy:
- Runtime / deployment:
- Public/private synchronization:
- Explicitly out of scope:

## Alternatives
- Chosen: <approach and reason>
- Rejected: <real alternative and one concise reason>

## Implementation order
1. <file, function/type signature, and behavior>

## Failure, recovery, migration, and rollback

## Validation plan
- Focused tests:
- Regression tests:
- Build/typecheck/lint:
- Manual or production-safe checks:

## Approval record

## Completion evidence
- Files changed:
- Commands and results:
- Deviations:
- Remaining risks/TODOs:
- Manual verification:
- Rollback:
```

Store feature-specific plans under `docs/<feature>/<date>/plan.md` when they need history. Do not turn this root file into a running backlog.
