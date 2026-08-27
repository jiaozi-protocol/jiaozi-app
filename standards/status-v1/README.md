# jiaozi.status.v1

Open specification for the signed revocation-freshness status credential used by
the Jiaozi Protocol.

- **`SPEC.md`** — the specification (draft for public review).
- **`test-vectors.json`** — deterministic vectors (fixed test key, fixed clock);
  any implementation should reproduce all expected results.
- **`conformance.mjs`** — the referee. Zero-dependency, independent verifier:
  `node conformance.mjs` runs the offline vectors;
  `node conformance.mjs https://your-deployment.example JP-XXXX-XXXXXX` probes a
  live issuer (shape, signature, key pinning, TTL, serial monotonicity, signed
  `unknown`).
- **`implementations.json`** — verified implementations registry. Want in? Open a
  PR adding your deployment; CI runs the conformance tester against it and the
  result is the verdict. Listed entries are re-tested daily.
- **`GOVERNANCE.md`** — how decisions are made (single-editor stage, stated
  honestly), versioning discipline, and the neutrality roadmap with concrete
  triggers.
- **`generate-test-vectors.mjs`** — regenerates the vectors from the reference
  implementation. It is maintained inside the reference monorepo
  (`standards/status-v1/` of the Jiaozi Protocol codebase) where `gdid-core` is
  built; in this standalone repo it is included for transparency.

Live issuer: `GET https://www.jiaozi.io/api/status/{certId}` ·
signing key: `GET https://www.jiaozi.io/api/status-key`

Spec text CC BY 4.0 · code MIT.
