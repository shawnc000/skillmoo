<!-- Thanks for contributing to SkillMOO! Keep this short. -->

## What & why

<!-- What does this change, and why? Link any issue: "Closes #123". -->

## Type

- [ ] Detection fix (false positive / missed detection) — **please add a regression test**
- [ ] New detection rule
- [ ] Bug fix
- [ ] Feature / CLI change
- [ ] Docs
- [ ] Other

## Checklist

- [ ] `npm run build` succeeds and `npm test` passes (or I've described why a test isn't applicable)
- [ ] For a detection change: I added a case (benign **and/or** malicious) so this can't regress
- [ ] I did not add a runtime dependency (the engine is intentionally dependency-free)
- [ ] The change keeps the CLI **local and read-only** (no new file writes, no network calls)

## Notes for the reviewer

<!-- Anything to know while reviewing? Trade-offs, follow-ups, etc. -->
