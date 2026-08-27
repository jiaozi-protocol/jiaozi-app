# Governance

This document says plainly how decisions get made here. It is short because the
project is young; it will grow only when reality demands it.

## Current stage: single-editor, open process

- **Editor:** Jiaozi Protocol (the reference operator). The editor merges PRs and
  has the final say on spec changes — stated honestly rather than hidden behind
  a committee that does not yet exist.
- **Everything is public:** issues, PRs, CI runs, the registry, and this file.
  No decision about the spec is made in private channels.
- **Your exit right is structural, not promised:** the spec is CC BY 4.0 and
  the code is MIT. Anyone can fork, rename, and take the community elsewhere.
  The editor keeps its role only by being a good editor.

## How changes are decided

| Change type | Process |
|---|---|
| Editorial (wording, typos, examples) | PR → editor review → merge |
| Behavioral (changes what implementations must do) | PR **must** include updated test vectors and conformance checks; CI must be green; editor merges only with a written rationale in the PR |
| Registry additions (`implementations.json`) | **No human gatekeeping.** The conformance CI is the referee: green = listed, red = not yet. Entries failing the daily re-run for 7 consecutive days are removed by PR. |

## Versioning discipline

- The `schema` string (`jiaozi.status.v1`) **is** the version.
- v1 wire behavior is frozen: no change may invalidate a previously conforming
  implementation. Anything incompatible goes to `jiaozi.status.v2` as a new
  schema, and v1 verifiers reject it by design.
- Test vectors are the normative record of wire behavior. If prose and vectors
  disagree, the vectors win until a clarifying release.

## The referee is code

Conformance disputes are settled by `conformance.mjs`, not by argument. If you
believe the tester itself is wrong, that is a spec defect: open an issue citing
the section, and the fix lands in tester + vectors + prose together.

## Neutrality roadmap

The editor commits to moving this specification to neutral stewardship
(donation to an established foundation such as DIF or the Linux Foundation,
or an equivalent arrangement) when either trigger fires:

1. Two or more independent implementations are operating in production and
   listed in the registry, or
2. a regulator, standards body, or major adopter requires neutral governance
   as a condition of adoption.

Until then, pretending a foundation exists would be theater; this document is
the honest substitute.

## Changing this document

By PR, same as everything else. Changes to the neutrality roadmap triggers
require a linked issue left open for comment for at least 14 days.
