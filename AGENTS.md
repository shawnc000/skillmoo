# Development workflow

These rules are the default implementation standard for every agent working in this repository. A more specific instruction in the current task takes precedence. In particular, when the user explicitly says to proceed without further confirmation after analysis, that instruction counts as approval for the scoped plan; it does not authorize broader or destructive work.

Repository knowledge map:

- `PLANS.md`: plan format and approval lifecycle for complex work
- `docs/architecture.md`: current system structure and repository boundaries
- `docs/business-rules.md`: product invariants that code alone does not explain
- `docs/deployment.md`: production, configuration, release, and rollback constraints
- `docs/testing.md`: test commands and minimum acceptance gates
- `docs/task-card-template.md`: the preferred input format for an individual task

## Before implementation

Work to minimize total rework, not merely time to first code.

## 1. Inspect before asking

Read the smallest relevant slice of the repository first:

- entry points and direct dependencies
- adjacent tests
- configuration and dependency manifests
- existing types, utilities, abstractions, and error-handling patterns
- runtime and deployment constraints

Do not ask questions whose answers can be discovered from the repository.
Report meaningful contradictions in the codebase instead of silently choosing
or creating a third convention.

## 2. Choose process by blast radius

Classify by behavioral and operational blast radius, not line count alone.

### Trivial

For a typo, copy change, rename, styling adjustment, or a change under roughly
20 lines with one obvious correct implementation and no wider behavioral impact:

- inspect local context
- implement directly
- run focused validation
- report the result

### Standard

For a localized feature or bug fix:

- summarize the goal and acceptance criteria
- list only implementation-changing assumptions
- name affected files and tests
- ask only genuinely blocking questions
- then implement

### High impact

For schema, authentication, payment, migration, deletion, public API,
architecture, permissions, concurrency, or cross-module changes:

Provide the following and stop before implementation, unless the current user
request has already explicitly authorized execution without another approval:

**Goal**

One paragraph restating the requested outcome and measurable acceptance criteria.

**Blocking questions**

Zero to three questions only. Ask only when different answers would materially
change the design or cause substantial rework. Include a recommended default.

**Assumptions**

Numbered, specific, falsifiable assumptions that can affect implementation,
covering only relevant areas:

- data and malformed inputs
- failure and recovery
- API and compatibility boundaries
- concurrency, idempotency, transactions, and ordering
- runtime and deployment environment
- explicit out-of-scope items
- tests and validation

**Plan**

Files to create or modify, key function or type signatures, implementation order,
migration and rollback requirements, and tests to run.

When choosing between real alternatives, name the rejected alternative and give
one concise reason.

Wait for approval when the task has not already granted it.

Use the format and lifecycle in `PLANS.md` for complex or high-impact work.

### SkillMOO impact defaults

Treat these as high impact unless repository inspection proves the requested change is documentation-only or otherwise isolated:

- model comparison or runtime-evaluation engines
- scoring formulas, grade thresholds, gates, or rubric versions
- batch Skill detection or repository ingestion
- billing, entitlements, quotas, or promotions
- user, session, report, feedback, or analytics data
- GitHub repository access, OAuth, tokens, or rate-limit behavior
- CLI/Web shared evaluation or retrieval logic
- safety scanner or optimizer invariant changes
- database or KV schemas and migrations

These normally qualify for direct implementation after local inspection and focused validation, provided they do not cross a boundary above:

- page copy
- report-card styling
- loading animation
- small responsive-layout fixes
- an isolated single-component bug

## 3. During implementation

Follow the approved or explicitly authorized plan.

Stop and report before continuing when:

- a material assumption is false
- the repository contradicts the approved design
- the change requires a broader public API, schema, security, or architectural impact
- destructive or irreversible work becomes necessary

Do not silently substitute a different design.

## 4. Completion

After implementation, report:

1. Files changed
2. Behavior implemented
3. Tests and commands run
4. Results
5. Deviations from the approved plan
6. Remaining risks or TODOs
7. Manual verification steps
8. Rollback steps when relevant
