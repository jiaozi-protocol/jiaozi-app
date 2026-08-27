# @jiaozi-protocol/gdid-core

Core primitives of [JIAOZI](https://www.jiaozi.io) — the open identity &
attestation layer for AI agents. Protocol specs and reference implementations
live in the [jiaozi-protocol](https://github.com/jiaozi-protocol) GitHub org.

```bash
npm install @jiaozi-protocol/gdid-core
```

## What's inside

- **DID documents** — `did:web` helpers and W3C DID Core–conformant document
  construction (`@context`, `Ed25519VerificationKey2020` with standard
  multibase `z6Mk…` keys), key rotation with owner binding.
- **`jiaozi.status.v1`** — signed revocation-freshness status credentials:
  build, sign, and verify short-TTL Ed25519 status assertions
  ([open spec](https://github.com/jiaozi-protocol/status-v1)).

```ts
import { verifyStatusCredential } from "@jiaozi-protocol/gdid-core/status";

const cred = await (await fetch("https://www.jiaozi.io/api/status/JIAOZI-2026-000001")).json();
const result = verifyStatusCredential(cred);
// { valid: true } or { valid: false, reason: "expired" | "bad_signature" | ... }
```

- **`jiaozi.attest.v1`** — attestation summary schema and validation for local
  agent health checks (software / TEE / cloud-attest trust levels).
- **Ed25519 keys** — generate, sign, verify; HD derivation
  (owner → domain → agent); standard multibase encoding utilities.
- **Credit merkle anchors** — hash-chained event anchoring with inclusion
  proofs (`jiaozi.credit.v1`).
- **Credential ID utilities** — `JIAOZI-YYYY-NNNNNN` formatting and validation,
  legacy `JP-` / `JJ-` normalization (historical IDs remain valid forever),
  GB/Z 185.2 OID identity-code composition.

Everything is dependency-free (Node.js `node:crypto` only) and verifiable
offline — trust decisions never require calling home.

## Related

- [`@jiaozi-protocol/sdk`](https://www.npmjs.com/package/@jiaozi-protocol/sdk) —
  high-level client (register / attest / resolve / verify).
- [`jiaozi.status.v1` spec + conformance tester](https://github.com/jiaozi-protocol/status-v1) —
  implement it yourself and get listed.

## License

MIT
