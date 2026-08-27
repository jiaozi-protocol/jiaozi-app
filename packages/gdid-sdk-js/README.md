# @jiaozi-protocol/sdk

TypeScript SDK for [JIAOZI](https://www.jiaozi.io) — register, attest, resolve
and verify AI-agent credentials. The underlying protocol is open: specs and
reference implementations live in the
[jiaozi-protocol](https://github.com/jiaozi-protocol) GitHub org.

```bash
npm install @jiaozi-protocol/sdk
```

```ts
import { Gdid } from "@jiaozi-protocol/sdk";

const gdid = new Gdid({
  baseUrl: "https://www.jiaozi.io",       // or https://www.jiaozi.tech (China)
  apiKey: process.env.JIAOZI_API_KEY,
});

await gdid.register({ name: "MyAgent", ownerPubkey: "zOwner..." });
await gdid.attest(summary);          // local health-check report
await gdid.resolve("JIAOZI-2026-000001");
await gdid.verify("did:web:...");    // authenticity check
```

Core surface: `register` / `verify` / `resolve` / `attest`.

## `attestationDegraded` in issuance responses

Responses from `POST /api/verify` (what `attest` calls) may carry
`attestationDegraded: true` next to `trustLevel`. It means the server-side
attestation chain tried higher-trust evidence plugins (TPM / TEE / cloud
remote attestation) but none was available, so the credential was issued at
the level the evidence actually supports — the `trustLevel` field in the same
response. Requesting a higher trust level never fails the request; it is
issued downgraded instead. Relying parties should base trust decisions on the
actual `trustLevel` (e.g. `requireTrust({ minLevel })` below);
`attestationDegraded` is informational only and does not affect credential
validity.

## Credential → permission: `requireTrust`

**Certified agents get more permissions.** Gate your tools on the visiting
agent's live `jiaozi.status.v1` credential — signature, freshness (short TTL),
revocation/suspension, trust level and the agent's self-declared attest.v1
`behaviorBoundary` are all checked locally, no network call needed.

Trust ladder (same medals as the portal): Bronze = `software` <
Silver = `cloud_attest` < Gold = `tee` / `tpm`.

```ts
import { requireTrust, presentationFromHeaders } from "@jiaozi-protocol/sdk";

// Framework-agnostic pure function
const writeGate = requireTrust({
  minLevel: "cloud_attest",          // Silver or above
  behaviors: ["write"],              // must sit inside the declared boundary
  verify: { trustedKeys: ["z..."], expectedIssuer: "https://www.jiaozi.io" },
});

const decision = writeGate(presentationFromHeaders(req.headers));
// → { allowed: true, trustLevel, certId, payload }
// → { allowed: false, reasonCode, reason, trustLevel }
```

Deny codes (each with a bilingual human-readable `reason`):
`no_credential` · `expired` · `insufficient_level` · `behavior_out_of_boundary`,
refined by `revoked` / `suspended` / `invalid_credential` for fail-closed paths.

Three verification policies (`policy` option): `"online"` (default — embedded
key + short-TTL freshness check), `"pinned"` (verify against locally pinned
`issuerKeys`, no did.json resolution, freshness still enforced) and
`"offline"` (pinned keys, freshness check skipped — the allow is explicitly
marked `freshness: "unverified"`, never a silent downgrade). `pinned` and
`offline` fail closed at build time without `issuerKeys`. A
`fetchStatusCredential` helper fetches a live credential from the default or a
custom status source.

Express-style one-liner (answers 401/403 with the readable reason itself):

```ts
import { requireTrustExpress } from "@jiaozi-protocol/sdk";

app.post("/api/write",
  requireTrustExpress({ minLevel: "cloud_attest", behaviors: ["write"] }),
  (req, res) => res.json({ ok: true, caller: req.jiaoziTrust }));
```

Credentials travel in the `x-jiaozi-status` header (raw or base64url JSON),
the optional boundary declaration in `x-jiaozi-boundary`. A runnable
three-tier MCP-style demo lives in
[`examples/mcp-trust-demo`](https://github.com/jiaozi-protocol/jiaozi-app/tree/main/examples/mcp-trust-demo).

## Multi-anchor resolution 多锚解析(抗单域故障,不是信任降级)

did.json 与 status 凭证由权威锚 `https://www.jiaozi.io` 供给,并由独立第二锚
`https://www.jiaozi.tech` 做**原字节镜像**。`resolveDidDocument` /
`resolveStatusCredential` 按锚列表顺序解析:主锚遇网络错误 / 超时 / 5xx 才
fallback 到镜像;2xx/4xx 都是权威答复,不触发切换。**多锚只是多一条取数
路径**——所有内容由同一把 SG 密钥签名,锚点不加分,验签仍走同一套
`verifyStatusCredential` / `requireTrust`;镜像被投毒验签照样不过,双锚全失败
照样 fail-closed 抛错,任何验证都不放宽。

The did.json and status endpoints are served by the authoritative anchor
`https://www.jiaozi.io` and **byte-mirrored** by the independent second anchor
`https://www.jiaozi.tech`. `resolveDidDocument` / `resolveStatusCredential`
walk an ordered anchor list: the mirror is only tried when the primary fails
at transport level (network error / timeout / 5xx); 2xx/4xx answers are
authoritative and never trigger fallback. Multi-anchor is **outage resistance,
not a trust downgrade** — every byte is signed by the same issuer key, an
anchor earns no trust by itself, verification runs the exact same code path,
a poisoned mirror still fails signature checks, and when every anchor is down
resolution fails closed.

```ts
import { resolveStatusCredential, requireTrust } from "@jiaozi-protocol/sdk";

const { credential, provenance } = await resolveStatusCredential(
  "JIAOZI-2026-000001",
  // { anchors: ["https://www.jiaozi.io", "https://www.jiaozi.tech"] } — the default
);

// provenance: which anchor answered + X-Jiaozi-Mirror* annotations
// { anchor, anchorIndex, viaMirror, mirrorSource, fetchedAt, stale, degraded }
if (provenance.degraded) {
  // 镜像 stale-if-error 命中或本地副本兜底:内容不新鲜,绝不静默当新鲜。
  // Low-risk display may accept by copy age (fetchedAt); high-risk operations
  // must fail closed — same ladder as requireTrust online/pinned/offline.
}

const decision = requireTrust({ policy: "pinned", issuerKeys: ["z6Mk..."] })({
  statusCredential: credential,
});
```

镜像陈旧供给的凭证签名仍可验,但其短时效已过:默认与 `pinned` 策略照样按
`expired` 拒绝,只有显式选 `offline` 才接受且结果带 `freshness: "unverified"`。
A stale copy's signature still verifies, but its short TTL has lapsed: the
default and `pinned` policies still deny it as `expired`; only an explicit
`offline` opt-in accepts it, marked `freshness: "unverified"`.

## Verifying revocation freshness (no account needed)

Any relying party can verify a credential's live status offline:

```ts
import { verifyStatusCredential } from "@jiaozi-protocol/gdid-core/status";

const cred = await (await fetch("https://www.jiaozi.io/api/status/JIAOZI-2026-000001")).json();
const result = verifyStatusCredential(cred); // Ed25519 + TTL + serial checks
```

The status credential format is an open spec:
[`jiaozi.status.v1`](https://github.com/jiaozi-protocol/status-v1).

## Python

The Python SDK lives in `packages/gdid-sdk-py` (`jiaozi-gdid` on PyPI):

```python
from jiaozi_gdid import Gdid

gdid = Gdid(base_url="https://www.jiaozi.io", api_key="...")
gdid.resolve("JIAOZI-2026-000001")
```

## License

MIT
