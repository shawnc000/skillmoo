# Setup Capsule v1 specification

Status: Approved by the user's explicit P4 execution authorization on 2026-08-02.

## Goal

Let a sender convert a valid, real, completed local verification receipt into a
privacy-minimized exact-setup file that a recipient can inspect and use to create
the existing immutable installation preview. The same inputs must create the same
capsule bytes and ID. No network request or target mutation may occur during
create, inspect, or prepare before the delegated installer preview step.

## Acceptance criteria

1. Only a valid, integrity-correct, complete, `verified-here`, real-provider
   receipt with goal passed and a non-regressed result can supply runtime
   evidence.
2. Every proposed Skill name, order, file count, and bridged verification digest
   maps to one `pilot-ready`, `embedded` artifact in the exact catalog version.
3. The capsule contains no suite title, task ID, prompt, output, observation,
   local filesystem path, provider URL, model name, invocation ID, receipt ID,
   or credential. Public pinned repository paths remain part of artifact identity.
4. Capsule identity is content-addressed and deterministic.
5. Inspect verifies schema, identity, integrity, catalog compatibility, and prints
   explicit setup/runtime/authentication boundaries.
6. Prepare refuses catalog drift and delegates to the existing catalog + setup
   preview without applying changes.
7. Web receipt review can download an eligible capsule locally and explains why
   an ineligible receipt cannot become replayable.
8. Simulation, provider error, tampering, mutable/local-only Skills, duplicate
   Skills, goal failure, regression/inconclusive outcomes, and different bundle
   bytes fail closed.
9. Public and private repositories keep the shared capsule protocol and CLI
   behavior in parity.

## Protocol

`skillmoo-setup-capsule/1.0`

Required top-level fields:

- `protocolVersion`
- `capsuleId`
- `createdAt`
- `setup`
- `senderEvidence`
- `replay`
- `limitations`
- `integrity`

`setup` contains:

- catalog protocol, CLI version, and catalog SHA-256;
- ordered artifact projections: name, artifact ID, bundle/payload SHA-256,
  pinned repository + commit + root tree/path, static assessment, license, and
  source limitations;
- exact setup SHA-256 from the receipt.

`senderEvidence` contains:

- source receipt payload SHA-256, verification protocol, suite/verifier/goal and
  environment hashes;
- aggregate result only;
- `attestation: local-self-attested`;
- `authentication: none`;
- `localValidation: receipt-schema-ledger-and-integrity-only`.

The exact completion time and sender evidence hashes are stable correlation
identifiers. They disclose no raw suite, environment, or receipt content but can
link capsules derived from the same private inputs; senders should share capsules
only with intended recipients.

`replay` contains:

- `setup: exact-catalog-artifacts`;
- `experiment: unavailable-private-suite`;
- the exact artifact order required by `catalog prepare`.

Protocol-owned objects reject unknown properties. CLI file readers accept at most
1 MiB, reject invalid UTF-8/JSON and duplicate JSON object keys before parsing,
and then run shared validation. Capsule creation contains no random data;
`createdAt` equals the receipt completion time. `capsuleId` and
`integrity.payloadSha256` are derived from canonical payloads.

The versioned identity bridge converts each validated artifact setup manifest to
the verification manifest representation by prepending the `.` root directory,
preserving every normalized entry, and hashing canonical `{ manifest }`. This
bridged digest, name, file count, and ordered position must equal the receipt.

## Assumptions

1. Catalog artifact names are unique and case-insensitively unique.
2. Verification setup bundle hashes use the same normalized complete-tree basis
   as the embedded artifact's setup manifest.
3. The exact CLI package contains the catalog payloads named by the capsule.
4. The recipient may inspect a capsule using a different CLI, but preparation
   must fail unless protocol, CLI version, catalog digest, and artifact identities
   match.
5. A sender-local result is informative evidence only; it is never inherited as
   the recipient's verified state.
6. No hosted sharing, authentication, deletion, or expiry behavior is in scope.
7. No schema migration is required; this is a new versioned file type.
8. Local catalog `quarantined` or `revoked` state overrides a capsule snapshot and
   blocks preparation. Offline inspection cannot claim online revocation freshness.

## Rejected alternatives

- Hosted anonymous receipt upload: rejected because safe ownership, withdrawal,
  bounded intake, strict limits, privacy projection, and atomic deduplication are
  not yet closed.
- Hosted authenticated upload in P4.1: rejected because it expands a setup-sharing
  value test into auth and governance infrastructure.
- Embed the full verification suite: rejected because existing privacy rules
  exclude raw task material and many suites are not publicly distributable.
- Call a receipt or capsule “certified”: rejected because no platform signer or
  independent verifier authenticates the model run.
- Allow mutable URLs/local bytes: rejected because the recipient could not replay
  the same setup safely.
- Create evidence-only capsules for ineligible setups: rejected because a file
  that cannot be prepared would make the beginner trust boundary ambiguous.

## Rollback

Remove the capsule command, Web download action, and new protocol module. Existing
verification receipts, catalog artifacts, setup plans, and installer behavior are
unchanged. Capsule files are inert JSON and do not require data migration.
