# Distribution and release

This repository does not host `skillmoo.com`. It publishes the auditable CLI/engine source and builds the npm package `skillmoo`.

## Build artifact

- `npm run build` bundles `cli/index.ts` and `src/lib/*` into `bin/skillmoo.mjs`.
- `package.json` is the CLI semantic-version source of truth.
- The generated binary is a release artifact; verify behavior from the built binary, not only TypeScript source.

## Release gate

1. Decide whether shared engine changes must be synchronized with the private hosted repository.
2. Record the public commit, corresponding private commit when relevant, npm version, rubric version, evidence/corpus version, test report, and rollback commit/tag.
3. Run every required command in `docs/testing.md`.
4. Update version and changelog when behavior changes. A stable rubric identifier does not replace a package patch version.
5. Inspect the npm tarball contents and integrity before publishing.
6. Publishing npm, pushing release tags, creating GitHub Releases, or changing default branches requires explicit authorization.
7. After publication, install/run the published version independently and verify version plus a safe and unsafe fixture.

## Rollback

Source rollback uses the recorded known-good commit. npm versions are immutable; do not overwrite a bad version—publish a corrected patch and document the superseded version. Never claim a source checkout and npm artifact are identical without recording and verifying the mapping.
