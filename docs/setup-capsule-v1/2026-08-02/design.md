# Setup Capsule v1 design

## Product goal

Give a beginner one safe action after receiving a setup: inspect the exact pinned
artifacts and create an immutable local preview. Do not require the recipient to
understand provenance formats, hashes, or verification statistics before acting.

## Core entities and boundaries

- **Local verification receipt**: private source evidence; never embedded.
- **Setup capsule**: public-safe, inert, content-addressed JSON projection.
- **Catalog artifact**: exact embedded bytes with source, license, manifest, and
  static assessment.
- **Setup plan**: recipient-local immutable preview.
- **Setup receipt**: recipient-local apply/rollback evidence.

The capsule crosses machines. Receipt internals, task material, model identity,
local paths, user identity, and target state do not.

## Main flow

```text
valid local verification receipt
            |
            v
catalog name + bundle digest match (fail closed)
            |
            v
public-safe deterministic capsule JSON
            |
       share as file
            |
            v
recipient inspect -> exact catalog check -> setup prepare
            |
            v
separate explicit apply -> separate recipient verification
```

## Interaction states

- Empty: generate/import a verification receipt first.
- Valid but ineligible: show the exact reason; keep ordinary receipt review.
- Eligible: one primary CTA, “Download exact-version setup”.
- Generating: local integrity and catalog match are visible.
- Success: downloaded file name + recipient commands.
- Error/tamper: no capsule CTA and no success metrics.

Advanced hashes and artifact source details stay in the downloaded capsule and
CLI inspect output. The Web primary surface leads with what can be replayed, what
cannot, and what happens next.

## Trust language

- “Exact setup replayable” means the same ordered catalog artifacts can be
  materialized from the exact CLI/catalog package.
- “Sender evidence” means the file declares an aggregate result. SkillMOO did not
  verify the sender identity or that the model run occurred.
- “Experiment not replayable from this file” means the private suite is absent.
- “Not SkillMOO signed” is always adjacent to the evidence state.

## Extension points

- a future hosted envelope may store only a validated capsule projection;
- real signer/authentication material can be added as a new envelope layer;
- a public suite reference may upgrade experiment replay independently;
- maintainer evidence and disputes remain append-only governance records that do
  not mutate a capsule or grade.
