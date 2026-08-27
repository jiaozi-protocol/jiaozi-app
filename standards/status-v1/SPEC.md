# jiaozi.status.v1 — Signed Revocation-Freshness Status Credential

**Status:** Draft for public review (v1.0-draft.1, 2026-08)
**Editor:** Jiaozi Protocol (https://www.jiaozi.io)
**Reference implementation:** `packages/gdid-core/src/status.ts` (TypeScript, Node.js 20)
**Live issuer:** `https://www.jiaozi.io/api/status/{certId}`
**License:** Spec text CC BY 4.0 · reference code MIT

---

## 1. Introduction

Certificate revocation is only useful if relying parties can learn about it *quickly*
and *verifiably*. Traditional mechanisms (CRLs, OCSP) suffer from long cache windows,
soft-fail clients, and unauthenticated transports — an attacker who can delay or block
revocation news gains more than one who forges a certificate.

`jiaozi.status.v1` is a minimal, transport-independent answer for AI-agent
certificates: a **short-TTL, Ed25519-signed status assertion** that any relying party
can verify offline in microseconds. It is deliberately small: one JSON payload, one
signature, one verification algorithm, fail-closed by default.

The schema is an open specification. Anyone may implement an issuer or a verifier
without permission from, or dependency on, the Jiaozi Protocol operator.

## 2. Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to
be interpreted as described in RFC 2119.

- **Issuer** — the party that knows the authoritative status of a certificate and
  signs status credentials for it.
- **Relying party (RP) / verifier** — any party that consumes a status credential to
  decide whether to trust an agent right now.
- **Certificate ID** — the protocol-level serial of an agent certificate, format
  `JIAOZI-YYYY-NNNNNN` (since 2026-08-08). Legacy prefixes remain valid: `JP-`
  IDs (issued 2026-07-26 … 2026-08-08) are used as-is; `JJ-` prefixes MUST be
  normalized to `JP-` before comparison. Issued IDs are never rewritten.

## 3. Data model

A status credential is a JSON object with exactly three top-level members:

```json
{
  "payload": { ... },
  "signature": "<base64url Ed25519 signature>",
  "publicKeyMultibase": "<issuer signing key, see §6>"
}
```

### 3.1 Payload fields

| Field | Type | Req. | Semantics |
|---|---|---|---|
| `schema` | string | MUST | Literal `"jiaozi.status.v1"`. |
| `certId` | string | MUST | Certificate ID this assertion is about. |
| `did` | string \| null | MUST | The subject DID, or `null` if unknown. |
| `status` | string | MUST | One of `active`, `suspended`, `revoked`, `unknown` (§3.2). |
| `trustLevel` | string \| null | MUST | Issuer-defined trust tier of the certificate, or `null`. |
| `revocationReason` | string | MAY | Human-readable reason; present only when meaningful. |
| `serial` | number | MUST | Monotonically increasing per issuer (§8). Reference implementation uses epoch milliseconds at signing time. |
| `signedAt` | string | MUST | ISO 8601 UTC timestamp of signing. |
| `expiresAt` | string | MUST | ISO 8601 UTC expiry. RPs MUST reject credentials past this instant (§7). |
| `issuer` | string | MUST | Issuer identifier (e.g. `https://www.jiaozi.io`). |

### 3.2 Status values

- `active` — certificate is currently in good standing.
- `suspended` — certificate is **reversibly locked** (aligned with the
  lock/unlock account lifecycle of GB/Z 185.3). RPs MUST treat `suspended` as
  "not currently trustworthy"; it MAY later return to `active`.
- `revoked` — certificate is **irreversibly** withdrawn.
- `unknown` — the issuer cannot make an assertion about this ID. RPs SHOULD treat
  `unknown` as untrusted under fail-closed policy.

## 4. Canonical JSON serialization

The byte string that is signed is `canonicalJson(payload)`, defined recursively:

1. `null`, booleans, numbers, and strings serialize as standard `JSON.stringify`.
2. Arrays serialize as `[` + comma-joined canonical serializations + `]`.
3. Objects serialize as `{` + comma-joined `"key":value` pairs **with keys sorted
   by Unicode code point** + `}`.
4. No insignificant whitespace anywhere.

Optional fields that are absent are simply omitted (they are not serialized as
`null`). Implementations MUST serialize the payload exactly this way before signing
or verifying; a single byte of difference invalidates the signature.

## 5. Signature

- Algorithm: **Ed25519** (RFC 8032), no prehash.
- Message: UTF-8 bytes of `canonicalJson(payload)`.
- `signature`: the 64-byte Ed25519 signature, **base64url-encoded without padding**.

## 6. Issuer public key encoding

`publicKeyMultibase` is the character `z` followed by the **base64url encoding
(no padding) of the raw 32-byte Ed25519 public key**.

> **Compatibility note.** Despite the field name, this encoding is *not* the
> multibase/base58btc `z...` encoding used by `did:key`. This is a known divergence
> of v1, kept for compatibility with deployed verifiers. A future v2 MAY migrate to
> standard multibase; v1 verifiers MUST implement the encoding as specified here.

Issuers SHOULD publish their current signing key at a well-known endpoint
(reference deployment: `GET https://www.jiaozi.io/api/status-key`), and RPs SHOULD
pin the set of keys they accept (§7, `untrusted_key`).

## 7. Verification algorithm

Given a candidate credential and optional pins, an RP MUST evaluate **in order**:

1. **Shape** — top-level members and payload fields are present with correct types
   and `schema === "jiaozi.status.v1"`; else fail `bad_shape`.
2. **Key pin** (optional) — if the RP maintains a trusted-key list and
   `publicKeyMultibase` is not in it, fail `untrusted_key`.
3. **Signature** — verify Ed25519 over `canonicalJson(payload)`; else fail
   `bad_signature`.
4. **Expiry** — if `now > expiresAt`, fail `expired`.
5. **Issuer pin** (optional) — if the RP expects a specific `issuer` string and it
   differs, fail `issuer_mismatch`.
6. **Serial floor** (optional) — if the RP has previously accepted serial *S* for
   this `certId` and the candidate `serial < S`, fail `serial_regression`.

Only after all checks pass may the RP act on `payload.status`.

**Fail-closed is the default posture:** on any failure, or when no fresh credential
can be obtained, the RP SHOULD treat the certificate as untrusted. Deployments MAY
document explicit fail-open exceptions for low-risk read-only contexts, but MUST NOT
fail open for actions involving funds, contracts, or data disclosure.

## 8. Serial monotonicity and replay protection

Short TTLs bound the staleness window; serials close the remaining gap. Because an
attacker who captured a still-unexpired `active` credential could replay it after a
revocation, RPs that cache anything SHOULD remember the highest accepted `serial`
per `certId` and reject regressions. Issuers MUST never sign two credentials for the
same `certId` where the later-signed one carries a lower `serial`.

## 9. TTL guidance

The reference deployment signs with a TTL of 60 seconds. Issuers SHOULD choose the
shortest TTL their infrastructure sustains; RPs SHOULD refresh at or before expiry
and MUST NOT extend a credential's life beyond `expiresAt` under any caching scheme
(the credential is deliberately *not cacheable* past its window — freshness is the
product).

## 10. HTTP transport (non-normative)

The credential is transport-independent. The reference deployment serves:

- `GET /api/status/{certId}` → `200` with a `StatusCredentialV1` JSON body for
  known IDs (including `revoked` and `suspended` — the *assertion* is signed, not
  the happy path). Unknown IDs return `404`, and the body still carries a signed
  `unknown` credential so no decision gap is left unsigned.
- `GET /api/status-key` → current issuer signing key.

## 11. Security considerations

- **Key compromise** — an attacker with the signing key can forge freshness. Issuers
  SHOULD use ephemeral signing keys rotated frequently, publish rotations at the
  status-key endpoint, and keep long-term issuance keys offline.
- **Clock skew** — RPs SHOULD allow small skew (≤ 30 s) when evaluating `expiresAt`,
  never more than the TTL itself.
- **Downgrade to `unknown`** — an attacker may try to serve `unknown` instead of
  `revoked`. Under fail-closed policy both deny trust, which is why fail-closed is
  the default.
- **Blocking the channel** — denial of status service degrades to denial of trust
  (fail-closed), not to acceptance. This inverts the incentive that plagues OCSP
  soft-fail.

## 12. Test vectors

`test-vectors.json` (same directory) contains deterministic vectors generated from a
fixed Ed25519 seed, covering: canonical serialization, a valid `active` credential,
a `revoked` credential with reason, an expired credential, a tampered payload, and a
serial regression. Implementations SHOULD verify against all vectors.
The generator is `generate-test-vectors.mjs`; regenerate with
`node standards/status-v1/generate-test-vectors.mjs`.

## 13. Versioning

The `schema` string is the version. Incompatible changes require a new schema string
(`jiaozi.status.v2`); verifiers MUST reject schemas they do not implement (this falls
out of check 1).

## 14. Regional co-signature extension: `jiaozi.status.sm2.v1` (optional)

A regional implementation MAY attach an additional co-signature over the same
payload, alongside — never instead of — the authoritative Ed25519 signature.
Verifiers that do not implement the extension MUST ignore it; the core
verification algorithm (§7) is unchanged.

The first registered extension is the Chinese national cryptography (国密)
endorsement produced by the China implementation (Q Jupiter Technology):

```json
{
  "payload": { ... },
  "signature": "<base64url Ed25519, authoritative>",
  "publicKeyMultibase": "z...",
  "smEndorsement": {
    "schema": "jiaozi.status.sm2.v1",
    "algorithm": "SM2-with-SM3",
    "signature": "<r||s, 128 lowercase hex, non-DER>",
    "publicKeyHex": "<04 || x || y, 130 hex uncompressed point>",
    "endorser": "cn-front-qiji",
    "signedAt": "<RFC 3339>",
    "ephemeral": false
  }
}
```

Rules:

1. The signed message is byte-identical to the Ed25519 case: the UTF-8 encoding
   of `canonicalJson(payload)` (§4).
2. Signature algorithm is SM2 (GB/T 32918) over the SM3 digest (GB/T 32905),
   with the default ZA user identifier `1234567812345678`. The signature is the
   raw `r || s` concatenation (128 hex chars), not DER.
3. The endorsement key is published at the regional implementation's
   `GET /api/status-key`; `ephemeral: true` means the key rotates on process
   restart and MUST NOT be pinned.
4. An endorsement is NOT a substitute for the authoritative signature. On a
   degraded (unsigned) replica response the endorsement only proves replica
   integrity; fail-closed verifiers MUST still reject for high-risk operations.

Related: `jiaozi.attest.v1` accepts an optional `softwareGeneHashSm3` field
(`"sm3:" + 64 hex`, GB/T 32905 digest of the same gene material as
`softwareGeneHash`), letting domestic verifiers audit the software gene under
the national-standard hash. `sha256` remains the primary digest for dedup and
international interop.
