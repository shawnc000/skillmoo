# ADR-008: Start P4 with offline replayable setup capsules

Status: Accepted

## Context

P4 calls for shareable, reproducible setup evidence. Existing verification
receipts are private, local-self-attested, and intentionally exclude raw task
material. Existing hosted report intake is anonymous and is not an acceptable
storage or ownership model for receipts. The catalog and installer already
provide a small exact-artifact, preview/apply/rollback path.

## Decision

P4.1 introduces an offline Setup Capsule. It is a content-addressed projection of
an integrity-valid real receipt and exact embedded catalog artifacts. It can
replay the setup, not the private experiment, and never claims platform signing.

Hosted upload, maintainer claims, public discovery, disputes, signatures, and
cross-model aggregation remain separate later decisions.

## Consequences

- The first increment is useful without auth, storage, production deployment, or
  privacy-sensitive upload.
- Only the four-artifact pilot can qualify initially; the product must disclose
  that narrow coverage.
- Sharing is a file workflow until hosted governance is ready.
- Recipient evidence remains independent; sender results do not transfer.
- The future hosted schema can wrap the capsule without changing local receipts.
