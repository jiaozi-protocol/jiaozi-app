# jiaozi-gdid

Python SDK for [JIAOZI](https://www.jiaozi.io) — register, attest, resolve and
verify AI-agent credentials. The underlying protocol is open: specs and
reference implementations live in the
[jiaozi-protocol](https://github.com/jiaozi-protocol) GitHub org.

```bash
pip install jiaozi-gdid
```

Requires Python 3.11+.

## Usage

```python
from jiaozi_gdid import Gdid

gdid = Gdid(
    base_url="https://www.jiaozi.io",   # or https://www.jiaozi.tech (China)
    api_key="your-api-key",             # only needed for write operations
)

gdid.register(name="MyAgent", owner_pubkey="zOwner...")
gdid.attest(summary)                     # local health-check report (jiaozi.attest.v1)
gdid.resolve("JIAOZI-2026-000001")
gdid.verify("did:web:...")               # authenticity + revocation check
```

Core surface: `register` / `attest` / `resolve` / `verify`, plus credit-trail
helpers (`submit_credit` / `anchor_credit` / `get_credit_proof`).

`resolve` and `verify` are public and need no API key; registration,
attestation and credit submission require one (get yours at
[jiaozi.io/integrate](https://www.jiaozi.io/integrate)).

## Credential → permission: `require_trust`

**持证的 agent 获得更多权限。/ Certified agents get more permissions.**
用来访 agent 的实时 `jiaozi.status.v1` 凭证给你的工具设闸——签名、新鲜度
(短时效)、吊销/锁定、信任等级、以及 agent 自述的 attest.v1
`behaviorBoundary` 全部本地校验,无需联网。/ Gate your tools on the visiting
agent's live `jiaozi.status.v1` credential — signature, freshness (short TTL),
revocation/suspension, trust level and the agent's self-declared attest.v1
`behaviorBoundary` are all checked locally, no network call needed.

信任阶梯(与门户奖牌一致)/ Trust ladder (same medals as the portal):
Bronze = `software` < Silver = `cloud_attest` < Gold = `tee` / `tpm`.

```python
from jiaozi_gdid import require_trust, presentation_from_headers

# 框架无关的纯函数 / Framework-agnostic pure function
write_gate = require_trust(
    min_level="cloud_attest",          # 银牌及以上 / Silver or above
    behaviors=["write"],               # 必须落在自述边界内 / must sit inside the declared boundary
    verify={"trusted_keys": ["z..."], "expected_issuer": "https://www.jiaozi.io"},
)

decision = write_gate(presentation_from_headers(headers))
# → TrustDecision(allowed=True, trust_level=…, cert_id=…, payload=…)
# → TrustDecision(allowed=False, reason_code=…, reason=…, trust_level=…)
```

拒绝码(每个都带中英双语的 `reason`)/ Deny codes (each with a bilingual
human-readable `reason`): `no_credential` · `expired` · `insufficient_level` ·
`behavior_out_of_boundary`,fail-closed 细分 / refined by `revoked` /
`suspended` / `invalid_credential` for fail-closed paths.

三种验证策略(`policy` 参数)/ Three verification policies (`policy`
option): `"online"`(默认,内嵌公钥验签 + 短时效检查 / default — embedded
key + short-TTL freshness check)、`"pinned"`(本地钉扎 `issuer_keys` 验签,
不解析 did.json,新鲜度照常 / verify against locally pinned `issuer_keys`,
no did.json resolution, freshness still enforced)、`"offline"`(钉扎验签,
跳过新鲜度,放行结果显式标注 `freshness="unverified"`,绝不静默降级 /
pinned keys, freshness check skipped — the allow is explicitly marked
`freshness="unverified"`, never a silent downgrade)。`pinned` 与 `offline`
缺 `issuer_keys` 时构建即报错(fail-closed)。`fetch_status_credential`
可从默认或自定义 status source 在线取新凭证。

凭证走 `x-jiaozi-status` 请求头(原始或 base64url JSON),可选的边界声明走
`x-jiaozi-boundary`。/ Credentials travel in the `x-jiaozi-status` header
(raw or base64url JSON), the optional boundary declaration in
`x-jiaozi-boundary`.

### FastAPI

```python
from fastapi import Depends, FastAPI
from jiaozi_gdid import require_trust_fastapi

app = FastAPI()
write_gate = require_trust_fastapi(min_level="cloud_attest", behaviors=["write"])

@app.post("/api/write")
def write(trust=Depends(write_gate)):   # 拒绝时自动回 401/403 / answers 401/403 on deny
    return {"ok": True, "caller": trust.to_dict()}
```

### Flask

```python
from flask import Flask, g
from jiaozi_gdid import require_trust_flask

app = Flask(__name__)

@app.post("/api/write")
@require_trust_flask(min_level="cloud_attest", behaviors=["write"])
def write():                             # 拒绝时自动回 401/403 / answers 401/403 on deny
    return {"ok": True, "caller": g.jiaozi_trust.to_dict()}
```

FastAPI / Flask 不是本包的硬依赖,只在调用集成函数时运行时导入。/
FastAPI / Flask are not hard dependencies; they are imported at runtime only
when you use the integration helpers.

### 离线验证 status.v1 / Verifying revocation freshness (no account needed)

```python
from jiaozi_gdid import fetch_status_credential, verify_status_credential

cred = fetch_status_credential("JIAOZI-2026-000001")
result = verify_status_credential(cred)  # Ed25519 + TTL + serial checks
```

语义与 [`@jiaozi-protocol/sdk`](https://www.npmjs.com/package/@jiaozi-protocol/sdk)
的 `requireTrust` 逐字对齐;凭证格式是开放规范
[`jiaozi.status.v1`](https://github.com/jiaozi-protocol/status-v1)。/
Semantics are aligned line-for-line with `requireTrust` in the TypeScript SDK;
the credential format is an open spec.

## Related

- [`@jiaozi-protocol/sdk`](https://www.npmjs.com/package/@jiaozi-protocol/sdk) —
  TypeScript SDK; its `requireTrust` credential-gated permission helpers are
  mirrored here as `require_trust`.
- [`jiaozi-validator`](https://pypi.org/project/jiaozi-validator/) — local
  health-check CLI that produces the `jiaozi.attest.v1` summary consumed by
  `attest`.
- [`jiaozi.status.v1` open spec](https://github.com/jiaozi-protocol/status-v1) —
  verify a credential's revocation freshness offline, no account needed.

## License

MIT
