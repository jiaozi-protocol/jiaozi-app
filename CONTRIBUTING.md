# Contributing

Thanks for your interest. This repository is a **read-only snapshot mirror** — each sync
replaces the entire git history, so **pull requests cannot be accepted here** (their base
commits disappear at the next sync). That is a property of our publishing pipeline, not a
lack of interest in your input. Everything below works fine across snapshots.

## Code: bug reports & feature requests

For the published packages (`@jiaozi-protocol/gdid-core`, `@jiaozi-protocol/sdk`,
`jiaozi-gdid`, `jiaozi-validator`) and the examples:

- Open a [GitHub Issue](https://github.com/jiaozi-protocol/jiaozi-app/issues) with
  reproduction steps and the package version, or
- Email **hello@jiaozi.io**.

Issues and their discussion threads persist across snapshot syncs. Fixes land in our
primary repository and appear here at the next sync, and in the package registries at the
next release. We will credit reporters in release notes unless you ask us not to.

## Standards: design review & feedback

This is the input we value most. The documents under `standards/` are open proposals:

| Draft | Status |
|---|---|
| `standards/status-v1` | published spec with test vectors and a conformance runner |
| `standards/delegation-v1` | draft under community review (W3C CCG) |
| `standards/tlog-v1` | draft under community review (W3C CCG) |

Ways to comment:

1. **GitHub Issue** on this repo with a `[standards]` title prefix — quote the section
   you are commenting on;
2. **W3C CCG mailing list** ([public-credentials archives](https://lists.w3.org/Archives/Public/public-credentials/))
   — reply on the existing thread for the draft;
3. **Email** hello@jiaozi.io if you prefer off-list discussion.

Drafts are revised in numbered versions (`-01`, `-02`, …). Substantive review comments
are addressed point-by-point in the revision notes, and reviewers are credited there
with their permission.

## Security issues

Do **not** open a public issue. Email **security@jiaozi.io** — see [SECURITY.md](SECURITY.md).
