# Task card template

Use one focused task card per request. Link to repository rules instead of repeating the full workflow.

```md
# Task
<One concrete feature, fix, or decision.>

## Goal
<User-visible outcome.>

## Must preserve
1. <Existing behavior or invariant that cannot regress.>

## Acceptance criteria
1. <Observable pass/fail result.>

## Constraints and out of scope
- <Runtime, compatibility, cost, security, or scope boundary.>

## Process
Impact: Trivial | Standard | High impact

For high-impact work: inspect the repository, produce a `PLANS.md`-compliant plan,
and wait for approval unless this task explicitly authorizes implementation.
```

Do not prescribe an implementation in the task card unless the implementation itself is a requirement. Let repository inspection determine affected files and reuse existing abstractions.
