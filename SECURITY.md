# Security Policy

SkillMOO is a tool that audits the safety of other people's code, so we hold our own to
the same bar.

## The guarantees this tool makes

The `skillmoo` CLI and detection engine are **100% local and read-only** by design:

- **It never writes to your files.** `scan`, `report`, and `plan` only read. `optimize`
  prints the improved skill to **stdout** — it never edits or overwrites anything on disk.
- **It never uploads your file contents.** Analysis runs entirely on your machine with no
  model and no network call. The one exception is fully opt-in: an interactive `scan` can
  publish a **grades-and-findings-only** web report (never your file bodies), and
  `--no-share` disables even that.
- **No account, no telemetry, no keys required** for the core CLI.

These properties are enforced by tests in the engine, not just documented here.

## Reporting a vulnerability

If you find a security issue in SkillMOO itself — for example a way to make the CLI write
to disk, exfiltrate content, or execute code from a scanned skill — **please do not open a
public issue.** Report it privately:

- Use **[GitHub Security Advisories](https://github.com/shawnc000/skillmoo/security/advisories/new)**
  (Security tab → *Report a vulnerability*), **or**
- email the maintainer via the address on the profile at
  [github.com/shawnc000](https://github.com/shawnc000).

Please include a description, reproduction steps, and the version (`npx skillmoo --version`).
We aim to acknowledge within **72 hours** and to ship a fix or mitigation as fast as the
severity warrants. Good-faith reports will be credited in the release notes unless you
prefer to stay anonymous.

## Reporting a *detection* problem (not a vulnerability)

A wrong grade — a **false positive** (a safe skill flagged) or a **false negative** (a
real risk missed) — is a correctness bug, not a security disclosure. Please report those
**publicly** with the
**[false-positive / missed-detection issue template](https://github.com/shawnc000/skillmoo/issues/new/choose)**
so the fix and its regression test can be discussed in the open. Zero-false-positive
accuracy is a core goal, and these reports are the highest-value contribution to it.

## Supported versions

SkillMOO is pre-1.0 and ships fixes on the latest published npm version. Please upgrade
(`npx skillmoo@latest`) before reporting.
