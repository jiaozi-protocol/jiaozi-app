# mcp-trust-demo — 凭证换权限的最小演示

**认证过的 agent 拿更多权限。** 这个 MCP 风格的演示服务器把工具分成三档:

| 工具 | 档位 | 要求 |
|---|---|---|
| `GET/POST /tools/read` | 公开 | 无证可用(只读) |
| `POST /tools/write` | 银级+ | 有效 `jiaozi.status.v1` 凭证,trustLevel ≥ `cloud_attest`(银 · 云证明) |
| `POST /tools/admin` | 金级 | trustLevel ≥ `tee`/`tpm`(金 · 硬件路径),且 `admin` 在 agent 自述的 attest.v1 `behaviorBoundary` 之内 |

服务端只用 SDK 的 `requireTrust`(纯函数用法)做验证:验签(Ed25519)、新鲜度(短 TTL 过期即拒)、吊销/锁定状态、等级门槛、行为边界,全部本地完成,不需要外呼。

## 运行

在仓库根目录:

```bash
npm run build -w @jiaozi-protocol/gdid-core -w @jiaozi-protocol/sdk   # 首次一次即可
node examples/mcp-trust-demo/server.mjs
```

服务器启动时扮演签发方,现场铸造 5 张演示凭证(铜/银/金/过期/吊销,TTL 10 分钟),并在
`GET /demo/credentials` 给出每张凭证的 header 值和可直接粘贴的 curl 命令。

一键跑完九个场景(另开一个终端):

```bash
node examples/mcp-trust-demo/demo.mjs
```

## 三档演示(curl)

凭证经 `x-jiaozi-status` header 出示(base64url 编码的凭证 JSON);具体 header 值从
`curl -s http://127.0.0.1:8787/demo/credentials` 的 `credentials.<tier>.header` 取。

```bash
# 档位 1:无证只读 → 200
curl -s http://127.0.0.1:8787/tools/read

# 无证写 → 401 no_credential
curl -s -X POST http://127.0.0.1:8787/tools/write

# 铜级写 → 403 insufficient_level(铜 < 银)
curl -s -X POST http://127.0.0.1:8787/tools/write -H "x-jiaozi-status: <bronze.header>"

# 档位 2:银级写 → 200
curl -s -X POST http://127.0.0.1:8787/tools/write -H "x-jiaozi-status: <silver.header>"

# 银级 admin → 403 insufficient_level(银 < 金)
curl -s -X POST http://127.0.0.1:8787/tools/admin -H "x-jiaozi-status: <silver.header>"

# 档位 3:金级 admin → 200
curl -s -X POST http://127.0.0.1:8787/tools/admin -H "x-jiaozi-status: <gold.header>"

# 金级但自述边界只有 read/write → 403 behavior_out_of_boundary
curl -s -X POST http://127.0.0.1:8787/tools/admin \
  -H "x-jiaozi-status: <gold.header>" -H "x-jiaozi-boundary: <narrowBoundaryHeader>"

# 过期凭证 → 403 expired;吊销凭证 → 403 revoked
curl -s -X POST http://127.0.0.1:8787/tools/write -H "x-jiaozi-status: <expired.header>"
curl -s -X POST http://127.0.0.1:8787/tools/admin -H "x-jiaozi-status: <revoked.header>"
```

拒绝响应都带机器可判的 `error`(reasonCode)和中英双语 `reason`,例如:

```json
{
  "error": "insufficient_level",
  "reason": "信任等级不足:需要 cloud_attest(银/Silver) 及以上,当前为 software / Insufficient trust level: requires cloud_attest(银/Silver) or above, credential carries software",
  "trustLevel": "software",
  "certId": "JIAOZI-2026-100001"
}
```

## 等级对照

沿用门户的奖牌映射:铜 = `software`,银 = `cloud_attest`,金 = `tee` / `tpm`。

## 适配器写法(@jiaozi/adapters)

同样的三档权限,用 `packages/adapters` 的 MCP 适配器重写:手工的 `gate()` 接线收敛为
一张声明式策略表 + 普通 handler,端点直接说 MCP 的 `tools/call`(JSON-RPC 2.0)。

```js
import { wrapToolHandler } from "@jiaozi/adapters";

const handleToolCall = wrapToolHandler(
  {
    tools: {
      read: { public: true },
      write: { minLevel: "cloud_attest", behaviors: ["write"] },
      admin: { minLevel: "tee", behaviors: ["admin"] },
    },
    trust: { verify: { trustedKeys: [issuerPublicKey], expectedIssuer: "my-issuer" } },
  },
  { read: readHandler, write: writeHandler, admin: adminHandler },
);
// HTTP 传输里:respond(await handleToolCall(jsonRpcRequest, { headers: req.headers }))
```

凭证两条进场通道等价:①MCP 规范预留的扩展位 `params._meta["jiaozi.io/status"]`
(凭证 JSON 原样、JSON 字符串或 base64url 均可,`jiaozi.io/boundary` 放行为边界);
②HTTP 传输时沿用 `x-jiaozi-status` / `x-jiaozi-boundary` header。拒绝按 MCP 规范返回
JSON-RPC error:未知工具 `-32602`,信任拒绝 `-32003`(实现自定义区间,message 中英双语,
`data.reasonCode` 机器可判)。判定语义与 SDK `requireTrust` 逐字一致,适配器只做翻译。

运行(adapters 包直接导出 TS 源码,需带 tsx 加载器):

```bash
node --import tsx examples/mcp-trust-demo/server-with-adapter.mjs   # 端口 8788
node examples/mcp-trust-demo/demo-adapter.mjs                        # 11 场景走查
```

## 接到自己的服务

Express 用户一行接入:

```js
import { requireTrustExpress } from "@jiaozi-protocol/sdk";
app.post("/api/write", requireTrustExpress({ minLevel: "cloud_attest", behaviors: ["write"] }), handler);
```

其他框架用纯函数 `requireTrust(options)` + `presentationFromHeaders(headers)`,详见 SDK README。
生产环境请用 `verify.trustedKeys` / `verify.expectedIssuer` 钉住真实签发方(本 demo 钉的是启动时现场生成的演示密钥)。
