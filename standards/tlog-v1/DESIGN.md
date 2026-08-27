# jiaozi.tlog.v1 — 凭证透明日志(Transparency Log)设计文档

**Status:** Design draft for public review(v1.0-design.2,revision -02,2026-08)
**Editor:** Jiaozi Protocol(https://www.jiaozi.io)
**Scope:** 仅设计,无实现(工单 L2 闸门:先公开征求意见 7 天,意见期结束后另立实现工单)
**License:** 文本 CC BY 4.0
**Revision:** -02(2026-08-25):吸收 Michael Beddows(Pyramidal)2026-08-18 公开评审的 12 项修订,
逐项清单见文末「附录 B. 修订说明」;`jiaozi.attest.v1` / `jiaozi.status.v1` 语义零变更。
上一版 -01 = v1.0-design.1(2026-08)。

> **零发明原则(zero-invention principle)**:本设计不引入任何自创密码学结构。
> Merkle 树、包含证明、一致性证明、监督者(Monitor)算法逐条对齐
> **RFC 9162(Certificate Transparency v2)**;架构角色、注册策略、隐私边界对齐
> **RFC 9943(IETF SCITT Architecture,2026-06 发布)**。每一节标注对应标准条款,
> 与标准的偏离在 §15「零发明自查表」中逐条声明并给出理由。
>
> **与 RFC 9162 的关系定性(revision -02)**:本设计是一个 **CT-derived checkpoint
> profile**(规范定义见 §7)——与 RFC 9162 为**算法层对齐**(Merkle 树与证明算法
> 逐字采用),**非 wire-level 兼容**(不产生、不消费 TLS presentation language 编码
> 与 `TransItem`)。RFC 9162 本身为 **Experimental** 类别;浏览器 CT 生态实际运行在
> RFC 6962 与 Static CT API 之上,本设计不寻求加入该生态,仅复用其数据结构与审计模型。

---

## 目录

1. 引言与动机
2. 术语与约定
3. 威胁模型
4. 日志条目 schema(`jiaozi.tlog.v1`,canonical JSON)
5. Merkle 树构造(对齐 RFC 9162 §2.1.1)
6. 包含证明与一致性证明(对齐 RFC 9162 §2.1.3 / §2.1.4)
7. 树头、签名树头与 checkpoint profile(CT-derived checkpoint profile 规范定义)
8. 日志参数(对齐 RFC 9162 §4.1)
9. 公开端点 `/api/tlog`(REST,JSON;对齐 RFC 9162 §5)
10. 每日锚定方案(git 外部锚点,weak broadcast channel)
11. 第三方镜像与审计指南(对齐 RFC 9162 §8.2 / §8.3)
12. 隐私边界(对齐 RFC 9943 §8)
13. 与 SCITT 架构(RFC 9943)的映射表
14. 分阶段实施(一期:单节点 Postgres)
15. 零发明自查表(标准对齐与偏离声明)
16. 参考文献
附录 A. W3C CCG / DIF 公开征求意见投递文案(英文)
附录 B. 修订说明(Revision History)

---

## 1. 引言与动机

JIAOZI Protocol 为 AI Agent 签发可验证身份凭证(凭证号 `JIAOZI-YYYY-NNNNNN`,
兼容历史 `JP-` / `JJ-` 前缀),并通过 `jiaozi.status.v1` 短 TTL 签名状态凭证
向依赖方(relying party)证明凭证的即时状态(active / suspended / revoked)。

当前架构中,签发方(Jiaozi Protocol 运营方)对"签发过什么、何时吊销了什么"拥有单方面的
叙事权:它可以对不同的查询者出示不同的历史(split view),也可以悄悄回改记录。
状态凭证解决的是"此刻状态是否新鲜可验",不解决"历史是否被篡改或选择性呈现"。

**透明日志(transparency log)** 补上这一块:所有凭证生命周期事件
(签发、锁定、恢复、吊销)进入一个 **append-only 的 Merkle 树日志**,
任何第三方可以:

- 拉取全量日志并独立重建树根(root hash);
- 验证任一事件的 **包含证明(inclusion proof)**;
- 验证任意两个时点之间的 **一致性证明(consistency proof)**,确认日志只增不改;
- 对照独立发布的每日锚点(anchor),发现签发方对不同人出示不同树头的行为。

这正是 Certificate Transparency 为 Web PKI 解决的问题(RFC 9162 §1:
"a critical lack of transparency in the operation of CAs"),
也是 SCITT 对签名声明(Signed Statement)给出的通用化定义(RFC 9943 §4:
transparency = "a consistent, append-only, cryptographically verifiable,
publicly available record of entries")。本设计把这两份已发布标准
落到 JIAOZI 的凭证事件上,不发明任何新结构。

### 1.1 设计目标

- **G1 可审计**:第三方无需许可即可镜像全量日志、复算树根、当独立 witness。
- **G2 防抵赖**:签发方无法在事后否认或悄悄改写任何已记录事件。
- **G3 防分叉**:split-view(对不同查询者出示不同历史)可以被检测。
- **G4 隐私中立**:日志内容不引入任何超出既有公开面的个人数据(见 §12)。
- **G5 一期可落地**:单节点 Postgres 表即可支撑(见 §14),不依赖区块链或分布式共识。

### 1.2 非目标

- 不做去中心化共识;日志由单一运营者维护,诚实性靠可审计性约束
  (与 CT 的信任模型一致,RFC 9162 §11.3)。
- 不在一期实现 COSE Receipt(RFC 9942)与 SCRAPI 端点;留作二期扩展(§14.2)。
- 不记录、不公开任何 Prompt、源码、行为数据;日志只含事件元数据与内容哈希(§12)。

## 2. 术语与约定

**MUST / MUST NOT / SHOULD / SHOULD NOT / MAY** 按 RFC 2119 / RFC 8174 解释。

| 术语 | 定义 | 来源 |
|---|---|---|
| Log entry(日志条目) | 一条凭证生命周期事件的 canonical JSON 记录 | 对应 RFC 9162 §4.3 "Log Entries" |
| Leaf hash(叶哈希) | `SHA-256(0x00 ‖ entry_bytes)` | RFC 9162 §2.1.1 |
| MTH(Merkle Tree Hash) | 树根哈希,构造见 §5 | RFC 9162 §2.1.1 |
| Tree head(树头) | `{treeSize, timestamp, rootHash}` | RFC 9162 §4.9 |
| STH(Signed Tree Head,签名树头) | 树头 + 日志身份 + Ed25519 签名 | RFC 9162 §4.10 |
| Inclusion proof(包含证明) | 证明某叶在某树头下的审计路径 | RFC 9162 §2.1.3 |
| Consistency proof(一致性证明) | 证明小树是大树前缀的路径 | RFC 9162 §2.1.4 |
| Monitor(监督者) | 持续拉取并验证日志的第三方 | RFC 9162 §8.2 |
| Witness(见证者) | 记录并交叉比对所见 STH 的第三方 | RFC 9162 §11.3(split-view 检测) |
| Transparency Service(TS) | 维护可验证数据结构并出具回执的服务 | RFC 9943 §3, §5.1 |
| Receipt(回执) | 已注册的签名证明(一期 = inclusion proof + STH) | RFC 9943 §3;RFC 9942 |
| Registration Policy(注册策略) | 决定哪些声明可入日志的显式策略 | RFC 9943 §5.1.1 |
| 凭证号(certId) | `JIAOZI-YYYY-NNNNNN`;历史前缀 `JP-` 原样保留,`JJ-` 归一为 `JP-` | `packages/gdid-core`(`formatCertId` / `normalizeCertId`) |

## 3. 威胁模型

被防御的对手是 **日志运营者本身**(即 Jiaozi Protocol 运营方)与网络中间人。
诚实运营者不需要日志;日志的意义在于让不诚实的运营者必然留下可检测的证据。
以下攻击面与缓解逐条对应 RFC 9162 §11「Security Considerations」:

| # | 攻击 | 缓解 | 标准依据 |
|---|---|---|---|
| T1 | 事后删除/篡改已记录事件 | append-only Merkle 树:任何改写导致新树根与旧 STH 的一致性证明不可构造 | RFC 9162 §2.1.4(consistency proof)、§11.3 |
| T2 | split view:对不同查询者出示不同树头 | 每日锚点入 git(§10)+ 独立 witness 交叉比对 STH | RFC 9162 §11.3("misbehaving logs"须靠 gossip / 外部通道发现) |
| T3 | 隐瞒事件(吊销了但不写日志) | 依赖方策略:status.v1 凭证与日志联合校验(吊销状态必须能在日志中找到对应 `cert_revoked` 条目,允许 MMD 窗口延迟) | 类比 RFC 9162 §8.1.6(客户端合规评估)、§4.1(MMD) |
| T4 | 伪造证明 | 叶/内部节点域分隔(0x00/0x01)保证二次原像抗性;证明验证算法逐条采用标准算法 | RFC 9162 §2.1.1(domain separation)、§2.1.3.2、§2.1.4.2 |
| T5 | 重放旧树头 | STH 含 `timestamp` 与 `treeSize`,依赖方拒绝 treeSize 回退;与 status.v1 的单调 serial 策略同构 | RFC 9162 §4.10;`jiaozi.status.v1` §"serial" |
| T6 | 通过日志挖掘个人数据 | 条目只含凭证号/事件类型/时间戳/内容哈希,详情本地留存、仅哈希上日志 | RFC 9943 §8(注册后不可撤回 ⇒ 最小化上日志内容)、§6.2(以哈希指代敏感载荷) |

**明确不在模型内**:签发私钥被盗(属密钥管理问题,见 RFC 9943 §9.4.2)、
运营者拒绝服务(可用性问题,镜像缓解)、量子对手。

## 4. 日志条目 schema(`jiaozi.tlog.v1`)

### 4.1 事件类型

对齐 `apps/api` 现有凭证生命周期语义(`certs.status` 状态机:
active ↔ suspended(可逆锁定),* → revoked(不可逆)):

| `eventType` | 语义 | 对应现有 API 行为 |
|---|---|---|
| `cert_issued` | 凭证签发 | 签发流程写入 `certs` 表 |
| `cert_suspended` | 锁定(可逆) | `setCertLock(lock=true)` |
| `cert_reinstated` | 解锁恢复 active | `setCertLock(lock=false)` |
| `cert_revoked` | 吊销(不可逆) | `revokeCert()` 写 `revocations` 表 |

新事件类型的加入 MUST 走本文档的版本修订流程,不得私下扩展
(类比 RFC 9162 §10.2.3 对 `VersionedTransTypes` 的注册管理)。

### 4.2 条目字段

一条日志条目是一个 JSON object,字段全集如下,**不允许多余字段**:

```json
{
  "schema": "jiaozi.tlog.v1",
  "eventType": "cert_revoked",
  "certId": "JIAOZI-2026-000123",
  "timestamp": "2026-08-10T12:34:56.000Z",
  "contentHash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

| 字段 | 类型 | 必填 | 语义 |
|---|---|---|---|
| `schema` | string | MUST | 字面量 `"jiaozi.tlog.v1"`。 |
| `eventType` | string | MUST | §4.1 之一。 |
| `certId` | string | MUST | 凭证号,`(JIAOZI|JP)-\d{4}-\d{6,9}`;写入前 MUST 经 `normalizeCertId` 归一(`JJ-` → `JP-`,统一大写)。 |
| `timestamp` | string | MUST | RFC 3339 UTC 毫秒精度;**日志接受时间**(对应 RFC 9162 §4.8 中 SCT `timestamp` 的语义:log 的收录时间,不是事件的业务时间),是 §8 MMD 的起算点。事件的**发生时间**记录在详情记录内,以 `contentHash` 承诺;两种时间的拆分语义与服务承诺见 §8。 |
| `contentHash` | string | MUST | `"sha256:" + 64 hex`,对该事件权威详情记录的**哈希承诺(commitment)**,构造见本节下文。详情由签发方留存,**不上日志**(§12);格式复用 `gdid-core` 的 `asSha256Prefixed` 约定。 |

事件详情记录(detail record)的内容因事件而异 —— 例如 `cert_issued` 的详情是
`jiaozi.attest.v1` 摘要,`cert_revoked` 的详情含 reason 与 revoked_by ——
但它们一律只以 `contentHash` 出现在日志中。这一"哈希指代敏感/大体积载荷"的手法
直接来自 RFC 9943 §6.2(Signing Large or Sensitive Statements),
也与本仓库 `jiaozi.credit.v1` 的既有原则一致("local detail, central hash only")。

**承诺构造(revision -02 收紧)**:详情记录 MUST 是一个**域分隔的 canonical
JSON 对象**——含一个标识详情类型的 schema 字面量字段(域分隔,防跨上下文哈希
混淆)——且 MUST 含一个 **≥128-bit 的新鲜随机 nonce 字段**(每事件独立生成)。
`contentHash` = `"sha256:" + hex(SHA-256(UTF-8(canonicalJson(detailRecord))))`。
nonce 与详情记录同存于签发方私有存储(参考 schema 见 §14.1),仅在**开承诺**
(向审计方/司法程序披露详情)时随详情一并披露,验证者复算哈希即可确认对应关系。
理由:详情记录字段可能是低熵的(枚举型 reason、有限操作者集合),无 nonce 的
裸哈希可被字典/穷举猜测从公开哈希反推私有内容;加入新鲜 nonce 后,`contentHash`
成为标准的隐藏承诺(hiding commitment),公开哈希不再泄露详情的任何信息。

### 4.3 Canonical 序列化

叶输入字节 = 条目 canonical JSON 的 UTF-8 编码。canonical 规则采用
**RFC 8785(JSON Canonicalization Scheme, JCS)** 语义:成员按 UTF-16 code unit
排序、无空白、ECMAScript 数字序列化。这与 `packages/gdid-core` 现有
`canonicalJson()`(递归 key 排序 + `JSON.stringify`)在本 schema 的字段域上
(全部为 string 字面量)产出逐字节一致的结果,协议全线(status.v1 / credit.v1 /
tlog.v1)共用同一 canonical 约定。

## 5. Merkle 树构造(RFC 9162 §2.1.1,逐字采用)

哈希算法 `HASH` = SHA-256(RFC 6234;在 RFC 9162 §10.2.1 哈希算法注册表内)。
给定有序条目列表 `D_n = {d[0], …, d[n-1]}`(d[i] 为 §4.3 的叶输入字节):

```text
MTH({})      = HASH()                                   # 空树 = 空串哈希
MTH({d[0]})  = HASH(0x00 || d[0])                       # 叶哈希,0x00 域分隔
MTH(D_n)     = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])) # k = 小于 n 的最大 2 的幂
```

要点(均为 RFC 9162 §2.1.1 原文要求,此处不重复论证):

- 叶与内部节点用 `0x00` / `0x01` 前缀域分隔,提供二次原像抗性;
- 树不要求满,形状由叶数唯一决定(奇数层**不复制**末节点);
- 叶索引 0 起,追加严格按序。

> **与仓库现有代码的关系(重要)**:`packages/gdid-core/src/credit.ts` 的
> `merkleRoot()` 采用"奇数复制末叶"(Bitcoin 风格)且无域分隔前缀,
> **不符合 RFC 9162,且复制式构造存在已知的重复叶歧义问题**。
> `jiaozi.tlog.v1` MUST NOT 复用该实现,MUST 严格按本节公式另行实现
> (实现属二期工单)。`credit.v1` 自身不受本文档影响。

## 6. 包含证明与一致性证明

### 6.1 包含证明(RFC 9162 §2.1.3)

生成算法 = §2.1.3.1 `PATH(m, D_n)` 的递归定义;验证算法 = §2.1.3.2 的
五步迭代(以 `leaf_index` / `tree_size` 的位运算沿路径重组根哈希,最后与
`root_hash` 比对)。本设计对算法**零修改**,仅规定 JSON 载体(§9.3)。

### 6.2 一致性证明(RFC 9162 §2.1.4)

生成算法 = §2.1.4.1 `PROOF(m, D_n)` / `SUBPROOF`;验证算法 = §2.1.4.2 的
七步迭代。同样零修改。一致性证明是 append-only 性质的机器可验形式:
若运营者改写了历史,它无法对新旧两个 STH 出具通过 §2.1.4.2 验证的证明。

## 7. 树头、签名树头与 checkpoint profile

> **定性(revision -02)**:本节与 §15 D-1 共同构成本设计 **CT-derived
> checkpoint profile** 的规范定义。它与 RFC 9162 为**算法层对齐**(§5/§6 的
> 哈希与证明算法逐字采用),**不是 wire-level 兼容**:本设计不产生、不消费
> RFC 9162 的 TLS presentation language 编码与 `TransItem` 结构。RFC 9162 为
> **Experimental** 类别,浏览器 CT 生态实际运行在 RFC 6962 与 Static CT API
> 之上;本设计不寻求加入浏览器 CT 生态。

### 7.1 STH 结构(字段对齐 RFC 9162 §4.9 / §4.10)

结构字段对齐 RFC 9162 §4.9(Merkle Tree Head:`timestamp` / `tree_size` /
`root_hash`)与 §4.10(STH = 树头 + `log_id` + 签名):

```json
{
  "payload": {
    "schema": "jiaozi.tlog-sth.v1",
    "logId": "https://www.jiaozi.io/api/tlog",
    "treeSize": 18342,
    "timestamp": "2026-08-10T12:35:00.000Z",
    "rootHash": "sha256:1f8e…c0aa"
  },
  "signature": "<base64url Ed25519 signature over canonicalJson(payload)>",
  "publicKeyMultibase": "z6Mk…"
}
```

- `logId`:日志的稳定标识,取日志 base URL 并全文固定。**偏离声明**:
  RFC 9162 §4.4 将 Log ID 定义为 **OID**(本文档 -01 版曾错误声称
  "§4.4 允许 log ID 的多种形态",revision -02 更正);本设计采用 URL 形态
  属对 §4.4 的偏离,归入 §15 D-1 一并声明。
- 签名算法:**Ed25519(RFC 8032)**,被签字节的精确构造见 §7.2;签名壳
  (`payload` / `signature` / `publicKeyMultibase` 三元组)与
  `jiaozi.status.v1` 完全同构,依赖方可复用同一验签代码路径。
- `publicKeyMultibase`:**informational(仅供参考,revision -02 降级)**。
  验证方 MUST 使用 pinned 公钥验签(引导与轮换见 §7.6:来源
  `/api/tlog/log-info` 并与锚点仓库交叉确认),MUST NOT 以 STH 内嵌的公钥
  验证该 STH 自身——被验证物自带的密钥不能为它自己作证。
- **偏离声明**:RFC 9162 用 TLS presentation language 编码 STH 并注册
  `TransItem` 类型;本设计改用协议既有的 canonical JSON + Ed25519 壳。
  字段语义一一对应、哈希与证明算法不变,仅序列化载体不同(详见 §15 D-1)。

依赖方处理 STH 的最低要求(对齐 RFC 9162 §4.10 与 §11.3;拒绝规则全集见 §7.3):

- MUST 用 pinned 公钥验签(MUST NOT 依赖内嵌 `publicKeyMultibase`);
- MUST 拒绝 `treeSize` 相对已见值回退的 STH;
- SHOULD 将所见 STH 与 §10 锚点及其他 witness 交叉比对;承担
  witness / monitor 角色的参与方,留存与交叉比对为 MUST(§10,revision -02
  自 SHOULD 升级)。

### 7.2 签名 transcript 与 canonicalization(规范性)

被签字节(signature transcript)的精确构造:

1. `payload` MUST 恰好包含 §7.1 所列五个字段,无多余字段。`schema` 字面量
   `"jiaozi.tlog-sth.v1"` 充当**域分隔**,防止与 `jiaozi.status.v1` 等
   同壳签名对象发生跨协议签名混淆。
2. transcript = `canonicalJson(payload)` 的 UTF-8 字节。canonical 规则 =
   RFC 8785(JCS,与 §4.3 同一约定):成员按 UTF-16 code unit 排序、
   无空白;`treeSize` 为非负整数 JSON number(ECMAScript 数字序列化,
   无前导零、无小数点),其余四字段均为 string。
3. `signature` = Ed25519(RFC 8032,**纯 Ed25519,非 Ed25519ph / Ed25519ctx**)
   对 transcript 字节直接签名所得 64 字节的 base64url 编码,编码约定与
   `jiaozi.status.v1` 签名壳既有实现逐字节一致。
4. 字段格式:`rootHash` 为 `"sha256:" + 64 hex(小写)`;`timestamp` 为
   RFC 3339 UTC 毫秒精度;`logId` 为固定 base URL 字符串。

### 7.3 验证方拒绝规则(规范性)

验证方 MUST **整体拒绝**(不得降级接受)满足以下任一条件的 STH:

- `payload` 字段缺失或含多余字段,或 `schema` ≠ `"jiaozi.tlog-sth.v1"`;
- `rootHash` 不符合 `sha256:` + 64 hex,或 `treeSize` 非非负整数,或
  `timestamp` 非合法 RFC 3339,或 `logId` 与 pinned 的日志身份不符;
- 以 pinned 公钥按 §7.2 构造 transcript 验签失败——包括"用 STH 内嵌
  `publicKeyMultibase` 验签通过、但 pinned 公钥验签失败"的情形,此情形
  按密钥不符处理,MUST 拒绝且 SHOULD 公开报告;
- `treeSize` 相对该验证方已见并接受的 STH 回退;
- 同一 `treeSize` 下 `rootHash` 与任何已见来源(锚点、其他 witness、
  §7.4 checkpoint 表示)不一致——此为 split-view 证据,处置见 §10 / §11.3。

验证方 MUST 以**自己重新 canonical 化** `payload` 所得字节作为 transcript,
不得直接信任传输层收到的原始字节序列(防止非 canonical 编码走私差异)。

### 7.4 C2SP tlog-checkpoint 并行表示(规范性,revision -02 新增)

自 revision -02 起,运营者 MUST 对每个对外发布的 tree head,在 §7.1 JSON STH
之外并行发布一份 **C2SP tlog-checkpoint**(<https://c2sp.org/tlog-checkpoint>)
**signed note**(<https://c2sp.org/signed-note>)表示,以便复用既有
checkpoint / witness 工具链。两种表示与同一 tree head 的对应关系为规范性定义:

| checkpoint 行 | JSON STH 字段 | 对应规则 |
|---|---|---|
| origin(第 1 行) | `logId` | = `logId` 去掉 `https://` scheme 前缀(C2SP 惯例用 schemeless origin),即 `www.jiaozi.io/api/tlog` |
| tree size(第 2 行) | `treeSize` | 十进制文本,数值 MUST 相等 |
| root hash(第 3 行) | `rootHash` | checkpoint 为 32 字节根哈希的 base64;解码后 MUST 与 `rootHash` 的 hex 部分逐字节相等 |
| signed-note 签名行 | — | Ed25519 签名,MUST 使用与 §7.1 STH 相同的日志签名密钥 |

约束:同一 `treeSize` 下,两种表示 MUST 承诺相同的根哈希;验证方 MAY 任选
一种表示消费;发现两种表示对同一 `treeSize` 给出不同根哈希,等同于
split-view 证据(§10)。JSON STH 的 `timestamp` 不出现在 checkpoint 体内
(C2SP checkpoint 无时间戳字段),时间承诺以 JSON STH 为准。

### 7.5 测试向量(结构占位,revision -02 新增)

profile 的一致性测试向量随实现工单交付,落位 `standards/tlog-v1/vectors/`。
本修订只固定向量集结构,**向量值本版不提供、不预先编造**:

| 文件(规划) | 覆盖内容 |
|---|---|
| `leaf-mth.json` | 叶哈希与 MTH 向量(空树 / 单叶 / 非满树,§5) |
| `proofs.json` | 包含证明与一致性证明向量(§6) |
| `sth-transcript.json` | STH 签名 transcript 向量:payload、canonical 字节(hex)、公钥、签名(§7.2) |
| `checkpoint.json` | 同一 tree head 的 JSON STH 与 C2SP checkpoint 双表示对应向量(§7.4) |
| `rejections.json` | 拒绝用例(负向量):§7.3 每条规则至少一例 |

### 7.6 密钥引导与轮换(规范性,revision -02 新增)

- **引导(bootstrapping)**:日志公钥经两条独立通道发布——
  ① `/api/tlog/log-info`(§9.6);② 锚点仓库(§10)随首个锚点提交留档。
  验证方 MUST 交叉确认两处一致后固定(pin);MUST NOT 以任何 STH 内嵌的
  `publicKeyMultibase` 作为引导来源。
- **计划轮换(rotation)**:① 运营者提前在 `/api/tlog/log-info` 与锚点仓库
  公告新公钥及生效点(treeSize 或日期);② 公告对象由**旧密钥签名**
  (交叉签名),并作为锚点提交留档;③ 重叠期内两把公钥并列发布,生效点前
  的 STH 用旧钥验、之后用新钥验;④ 验证方确认交叉签名与锚点一致后更新
  pinned 公钥;⑤ 旧公钥永久保留,用于验证历史 STH。
- **密钥泄露(非计划)**:无法以交叉签名背书时,按 RFC 9162 §4.13 日志关停
  流程处理——公告、冻结最终 STH、日志转只读留存,另立新日志(新 `logId`、
  新密钥)重新引导。泄露密钥签出的、超出冻结点的任何 STH 一律无效。

## 8. 日志参数(RFC 9162 §4.1)

RFC 9162 §4.1 要求日志运营者公开一组参数;`jiaozi.tlog.v1` 的对应参数集:

| 参数 | 值 | RFC 9162 §4.1 对应项 |
|---|---|---|
| Base URL | `https://www.jiaozi.io/api/tlog` | Base URL |
| 哈希算法 | SHA-256 | Hash Algorithm |
| 签名算法 | Ed25519(RFC 8032) | Signature Algorithm |
| 日志公钥 | 部署时发布(multibase,`/api/tlog/log-info` 可查,§9.6) | Public Key |
| Log ID | = Base URL(**偏离**:RFC 9162 §4.4 定义 Log ID 为 OID,本设计用 URL,声明于 §15 D-1) | Log ID(§4.4,偏离声明见 §7.1 / §15 D-1) |
| **MMD**(Maximum Merge Delay) | 24 h:自**日志接受**(条目 `timestamp`,§4.2)起至多 24 小时内 MUST 被并入某个已发布 STH。对齐 RFC 9162 §4.1 的 MMD 语义(-01 版误从"事件发生"起算,revision -02 更正) | Maximum Merge Delay |
| **Occurrence-to-acceptance latency**(本设计新增服务承诺,非 RFC 9162 参数) | 24 h:凭证生命周期事件自**发生**(权威业务动作生效)起至多 24 小时内 MUST 被日志接受。一期写路径与业务动作同事务提交(§14.1),该延迟实际 ≈ 0;承诺值为对外上限 | —(独立承诺,见表下说明) |
| STH 发布频率 | 有新条目时至少每小时一次;无新条目不强制发新 STH | STH Frequency(§4.10 禁止无意义高频发 STH 以防跟踪,同样适用) |
| 起止时间 | 上线时公布;日志关停按 RFC 9162 §4.13 流程(提前公告、最终 STH 冻结、只读保留) | Temporal Coverage / §4.13 |

**时间语义拆分(revision -02)**:条目 `timestamp` = 日志接受时间,是 MMD 的
起算点;事件**发生时间**记录于详情记录内、以 `contentHash` 承诺(§4.2),
开承诺时可验——两者 MUST NOT 混同。两项参数合成即
**occurrence-to-inclusion latency** 这一独立服务承诺:事件发生后至多
**48 h**(occurrence-to-acceptance 24 h + MMD 24 h)内 MUST 出现在某个
已发布 STH 中(-01 版把它与 MMD 混同为单一 24 h 声明,revision -02 拆分)。
occurrence-to-acceptance 承诺的外部审计路径:任何观察者可将自己经
`jiaozi.status.v1` / 公开状态端点观察到的状态变更时刻,与日志中对应条目的
`timestamp` 比对(§11.4 联合校验的推论);若差值持续超出承诺值,即为运营者
违反该承诺的公开证据。事件发生后进入**已锚定**树头的最坏时限推导见 §10。

## 9. 公开端点 `/api/tlog`(REST,JSON)

端点集合 = RFC 9162 §5 客户端消息的 REST/JSON 转写,逐一对应;
**不提供公开提交端点**(RFC 9162 §5.1 的 submit-entry 无对应物):
条目只由签发管线内部追加。用 SCITT 的语言表述,这是一条显式的
**Registration Policy**(RFC 9943 §5.1.1):"仅运营者签发管线产生的
生命周期事件可注册",该策略本身随本文档公开,满足 §5.1.1 对策略
透明化的要求。

所有端点:`GET`,无鉴权,响应 `application/json;charset=utf-8`,
SHOULD 设置合理的 `Cache-Control`(STH 短缓存、按 treeSize 参数化的
证明可长缓存)。错误响应统一 `{ "error": "<code>", "message": "…" }`。

### 9.1 `GET /api/tlog/sth` — 最新签名树头

对应 RFC 9162 §5.2(Retrieve Latest STH)。无参数,返回 §7.1 的 STH 对象。

### 9.2 `GET /api/tlog/sth-consistency?first=<m>&second=<n>` — 一致性证明

对应 RFC 9162 §5.3。`first` / `second` 为两个 treeSize(`0 < m < n`)。

```json
{ "consistencyPath": ["sha256:…", "sha256:…"] }
```

依赖方按 §6.2 验证。`m`/`n` 无效时返回 400(对应 §5.3 对错误输入的要求)。

### 9.3 `GET /api/tlog/proof-by-hash?hash=<leafHash>&treeSize=<n>` — 包含证明

对应 RFC 9162 §5.4(Retrieve Merkle Inclusion Proof from Log by Leaf Hash)。
`hash` 为 §5 定义的叶哈希(`sha256:` 前缀十六进制)。

```json
{
  "leafIndex": 17801,
  "auditPath": ["sha256:…", "sha256:…"]
}
```

### 9.4 `GET /api/tlog/entries?start=<i>&end=<j>` — 拉取条目区间

对应 RFC 9162 §5.6(Retrieve Entries and STH from Log)。0 起闭区间;
服务端 MAY 截断返回数量(§5.6 允许,客户端按返回量续拉),并附当前 STH:

```json
{
  "entries": [
    {
      "leafIndex": 17800,
      "entry": { "schema": "jiaozi.tlog.v1", "eventType": "cert_issued", "certId": "JIAOZI-2026-000123", "timestamp": "…", "contentHash": "sha256:…" }
    }
  ],
  "sth": { "payload": { … }, "signature": "…", "publicKeyMultibase": "…" }
}
```

`entry` 返回的是原始条目 JSON;镜像方 MUST 自行 canonical 化后复算叶哈希,
不信任服务端给出的任何中间哈希(与 RFC 9162 §5.6 中"客户端应把无法识别的
叶当作不透明输入验证完整性"同一精神)。

### 9.5 `GET /api/tlog/entry?certId=<id>` — 按凭证号索引(低量客户端便利端点)

RFC 9162 无此端点(CT 靠 Monitor 全量扫描)。**推荐验证路径是 §11 的全量
镜像**(revision -02 定位调整):镜像把依赖方的查询兴趣留在本地,不向运营者
暴露关注对象。本端点降级定位为**无力维护镜像的低量客户端的只读便利索引**,
返回该凭证号名下全部条目的 `leafIndex` 列表。它不参与任何信任判定 ——
依赖方拿到 `leafIndex` 后仍走 §9.3/§9.4 验证 —— 故不构成密码学结构发明,
属 RFC 9943 §5.1.4(Adjacent Services,"可在 TS 旁提供检索类附属服务")
允许的附属服务(详见 §15 D-3)。

**定向查询的隐私风险与最小留存(规范性,revision -02 新增)**:按 certId
定向查询会向运营者暴露"谁在关心哪张凭证"。为此:① 运营者对本端点的访问
日志 MUST **最小留存**——仅保留运维排障所必需的最短期限,MUST NOT 将查询
记录用于画像、关联分析或向第三方披露;② 对查询隐私敏感的依赖方 SHOULD
改用 §11 全量镜像。另见 §12.1。

### 9.6 `GET /api/tlog/log-info` — 日志参数发布

发布 §8 参数表(含日志公钥)。职能对应 SCRAPI 草案 §2.1 的
`/.well-known/scitt-keys`(依赖方由此发现验回执/验 STH 的公钥);
二期若实现 SCRAPI,则同时在 `/.well-known/scitt-keys` 暴露同一密钥集(§14.2)。

## 10. 每日锚定方案(git 外部锚点,weak broadcast channel)

Split-view 攻击(T2)无法靠日志自身发现,RFC 9162 §11.3 明确指出需要
带外通道(gossip / 多点观察)交叉比对 STH。一期采用 git 仓库作为公开
广播通道之一,revision -02 对其性质如实定性并收紧验证义务:

- **锚点文件**:每日 UTC 00:10,把当日最新 tree head 的**两种表示**写入
  公开 git 仓库:`docs/tlog-anchors/YYYY/YYYY-MM-DD.json`(§7.1 JSON STH,
  逐字节保留)与 `docs/tlog-anchors/YYYY/YYYY-MM-DD.checkpoint`
  (§7.4 C2SP signed note)。
- **定性:weak broadcast channel(revision -02 更正)**。git 锚定提供的是
  **作者出处(authorship provenance)与弱外部时间戳**——证明运营者在某时刻
  公开发布过该 STH——**不提供全局一致性**:代码托管平台不是共识系统,
  无法保证所有观察者看到同一份仓库历史。force-push 改写锚点历史的
  **可检测性是有条件的**:只有事先克隆/留存了旧 commit 的观察者才能发现
  改写并持有证据;平台自身不承诺保留被覆盖的历史(-01 版把 force-push
  近乎当作无条件可观测,系高估,revision -02 更正)。
- **独立留存与交叉比对是检测模型的规范性组成部分(revision -02 自 SHOULD
  升级为 MUST)**:本设计的 equivocation 检测模型规范性地依赖"运营者之外
  存在独立留存的 checkpoint 副本并被交叉比对"。凡承担 witness / monitor
  角色的参与方 MUST:① 长期留存所见 STH / checkpoint(含锚点仓库的克隆);
  ② 定期比对——ⓐ 锚点仓库相邻两日 STH 之间的一致性证明(§9.2);
  ⓑ 实时 `/api/tlog/sth` 与锚点是否同源(同一 `treeSize` 的 `rootHash`
  必须一致);ⓒ 同一 tree head 的 JSON STH 与 checkpoint 双表示是否一致
  (§7.4)。若不存在任何独立留存副本,本节锚定**不构成** split-view 防御。
- **锚定间隔与时限推导(revision -02 随 §8 时间语义拆分改写)**:锚点为
  日粒度。自日志接受起:MMD 24 h(§8)+ 至多一日的锚定间隔 ⇒ 已接受事件
  最迟在**接受后 48 h** 内进入某个已锚定树头;再叠加 occurrence-to-acceptance
  承诺(24 h,§8),事件**发生**后最坏 **72 h** 内被锚定(一期同事务写路径
  下实际 ≈ 48 h)。

**先例定位(revision -02 补正)**:Go checksum database 与 Sigstore Rekor
是 "signed checkpoint + 独立审计 / witness" 模型的先例——它们支撑的是
checkpoint 交叉比对,而非 git 锚定本身;把 Merkle 根发布到**外部既有广播
通道**的直接先例是 **Keybase**(将其 Merkle 根锚定到 Stellar 链)。本设计
的 git 通道取 Keybase 的外部通道思路,checkpoint 格式对齐前者生态(§7.4)。

**扩展节(非一期)**:更强的外部锚定 —— RFC 3161 时间戳、公链 OP_RETURN、
witness cosigning(C2SP tlog-witness,§14.2)—— 均只是把同一个 32 字节
rootHash 提交到更强的外部介质,不改变日志本体结构,留待后续工单按需追加。

## 11. 第三方镜像与审计指南

任何人无需许可即可镜像与审计。**全量镜像是推荐验证路径(RECOMMENDED,
revision -02 定位调整)**:相比 §9.5 定向查询,镜像把查询兴趣留在本地、
不向运营者暴露关注对象,且镜像方自动具备 witness 能力;二期全量镜像的
传输格式参考 C2SP tlog-tiles(§14.2)。以下流程是 RFC 9162 §8.2(Monitor)
两个算法的直接转写,步骤编号与原文对应。

### 11.1 全量引导(§8.2 第一算法)

1. `GET /api/tlog/sth`,取当前 STH;
2. 验证 STH 签名(§7.1–§7.3;pinned 公钥来自 `/api/tlog/log-info`,并与锚点仓库交叉确认,§7.6);
3. 以 `GET /api/tlog/entries` 分页拉全 `[0, treeSize)` 条目;
4. (领域检查)按业务关心的凭证号检查条目 —— 例如自家 agent 的凭证有无
   未预期的 `cert_revoked`;
5. 本地按 §5 复算 MTH,MUST 与 STH 的 `rootHash` 一致,否则丢弃并公开报告。

### 11.2 持续跟进(§8.2 第二算法)

1. 定期 `GET /api/tlog/sth`,直到出现 `treeSize` 更大的新 STH;
2. 验签;
3. `GET /api/tlog/entries?start=<旧treeSize>&end=<新treeSize-1>` 拉增量;
4. 领域检查同上;
5. 二选一:①用增量条目从旧根推算新根;或 ②`GET /api/tlog/sth-consistency`
   取一致性证明并按 §6.2 验证;
6. 回到第 1 步。

### 11.3 当独立 witness

- MUST 长期保存所有见过的 STH / checkpoint(它们是运营者的签名承诺,即作弊
  时的呈堂证据;revision -02 自 SHOULD 升级,理由见 §10——独立留存是检测
  模型的规范性组成部分);
- MUST 与 `docs/tlog-anchors/` 及其他 witness 交换/比对 STH:发现同一
  `treeSize` 下不同 `rootHash`,或一致性证明验证失败,即为日志失信的
  密码学证据,SHOULD 公开披露(处置原则同 RFC 9162 §11.3:失信日志应被
  依赖方集体弃用);
- 审计角色分工(monitor 查内容、auditor 查证明、两者信息互通)见 RFC 9162 §8.3。

### 11.4 与 status.v1 的联合校验(依赖方 SHOULD)

收到 `status: "revoked"` 的 status.v1 凭证后,依赖方 SHOULD 在 MMD 窗口后
于日志中确认对应 `cert_revoked` 条目存在(§9.5 索引 + §9.3 证明);
反之,若日志中存在某凭证的 `cert_revoked` 条目而权威 status 端点仍返回
active,即 T3(隐瞒/不一致)的直接证据。

## 12. 隐私边界

设计准则:**日志一旦写入永不可删**(append-only 的定义使然,RFC 9943 §8
明确警告注册内容无法事后撤回),因此上日志的信息必须最小化到"事后永远
不后悔公开"的程度。

| 进日志 | 不进日志(只以 `contentHash` 指代,详情签发方本地留存) |
|---|---|
| 凭证号 `certId`(本就是公开可查的序列号) | 主体身份信息:agent 名称、所有者信息、组织认证材料 |
| 事件类型(4 种,§4.1) | 公钥、DID 文档内容(公开面已有其发布渠道,不在日志重复) |
| 日志收录时间戳 | 吊销理由 `reason`、操作者 `revoked_by`(自由文本,可能含个人数据) |
| 内容哈希 `sha256:…` | attest 摘要全文、行为边界声明、任何 Prompt/源码/评分细节 |

- 哈希指代的手法与合规性论证:RFC 9943 §6.2(大体积或敏感载荷以哈希入签名
  声明,原文留在带外)。
- `certId` → 主体的关联本身不因日志新增:`/lookup` 与 status 端点已提供
  同等映射。日志新增的唯一信息是**事件时间线**,这正是透明性的目的物。
- 跨境边界:日志条目仅含摘要/哈希/凭证元数据,符合本项目"跨境只传摘要/
  哈希/证书元数据"的硬约束。
- 依 RFC 9162 §4.10 的同一考量,STH 发布频率设下限间隔,避免高频 STH
  成为查询者的跟踪信标。

### 12.1 定向查询的隐私(revision -02 新增)

§9.5 按凭证号定向查询会向运营者暴露查询者的关注对象("谁在关心哪张凭证")。
规范性缓解见 §9.5:运营者对该端点访问日志 MUST 最小留存、MUST NOT 用于
画像/关联分析/对外披露;根本性缓解是 §11 全量镜像(推荐验证路径,查询兴趣
不出本地)。

### 12.2 顺序编号的排序信息泄露(revision -02 新增,已知考量)

凭证号 `JIAOZI-YYYY-NNNNNN` 为顺序编号。日志条目按 certId 汇集后,会泄露
**签发顺序与大致签发量**(顺序序列号的经典计数问题)。如实声明:

- 该号段格式是既有产品面,已有凭证在外流通,**短期不改**编号方案;
- 在 tlog 条目内改用**不透明标识符**(切断"日志条目 ↔ 编号顺序"的直接
  关联)列为**未来评估项**:它会同时削弱 §9.5 索引与 §11.4 联合校验的
  可用性,须整体权衡后经本文档修订流程引入,本版不改变条目 schema;
- 在此之前,依赖方与被记录主体应知悉:日志额外公开的排序/计量信息以此
  为上限,不含 §12 表右列的任何内容。

## 13. 与 SCITT 架构(RFC 9943)的映射表

| SCITT 概念(RFC 9943 §3 术语) | jiaozi.tlog.v1 对应物 | 对齐程度 |
|---|---|---|
| Transparency Service(TS) | `/api/tlog` 服务(Jiaozi Protocol 运营) | 单租户 TS,Issuer 身份 = logId(§5.1 允许单一 Issuer 身份) |
| Issuer | Jiaozi Protocol 签发管线(唯一注册者) | 收窄:仅运营者自身(§9 注册策略) |
| Statement / Artifact | 凭证生命周期事件详情记录(本地留存) | 以哈希指代(§6.2 手法) |
| Signed Statement | 日志条目(§4)——条目本身不单独带 COSE 签名,由 STH 签名承诺整树 | **偏离**,见 §15 D-2 |
| Registration | 签发管线向日志追加条目 + 并入 STH | 对应 §6.3 注册流程(先注册后出回执) |
| Registration Policy | "仅运营者生命周期事件可注册",随本文档公开 | §5.1.1(策略须透明) |
| Verifiable Data Structure(VDS) | RFC 9162 Merkle 树(§5) | RFC 9943 §4 明示 CT(RFC 9162)是其 transparency 定义的实例 |
| Receipt | 一期:inclusion proof + STH(JSON);二期:COSE Receipt(RFC 9942) | 一期偏离,见 §15 D-2 |
| Transparent Statement | 条目 + 其 receipt 的组合(依赖方自行装配) | 概念对应 §7 |
| Auditor / Relying Party | §11 的 monitor / witness / 依赖方 | 直接对应 |
| Append-only Log | §5–§6 的 Merkle 日志 | 直接对应(§9.1 "Ordering of Signed Statements" 的全序要求由叶索引满足) |

## 14. 分阶段实施

### 14.1 一期:单节点 Postgres(设计参考,非实现)

一期规模(日志条目 ≪ 10^7)下,树不必物化存储:只存叶,树根与证明
按需从叶区间现算(MTH 定义是纯函数,§5)。建议表结构 **仅作设计参考**:

```sql
-- 参考 schema(设计文档用途,非交付物)
CREATE TABLE tlog_entries (
  leaf_index   BIGINT PRIMARY KEY,          -- 0 起、连续、只增(注册时在事务内分配)
  entry_json   JSONB   NOT NULL,            -- §4.2 条目原文
  leaf_input   BYTEA   NOT NULL,            -- canonical JSON 的 UTF-8 字节(§4.3,固化防重算歧义)
  leaf_hash    BYTEA   NOT NULL UNIQUE,     -- SHA-256(0x00 || leaf_input)(§5)
  cert_id      TEXT    NOT NULL,            -- 冗余列,支撑 §9.5 索引
  event_type   TEXT    NOT NULL CHECK (event_type IN
                 ('cert_issued','cert_suspended','cert_reinstated','cert_revoked')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX tlog_entries_cert_idx ON tlog_entries (cert_id);

CREATE TABLE tlog_sth (
  tree_size    BIGINT PRIMARY KEY,
  root_hash    BYTEA  NOT NULL,
  signed_at    TIMESTAMPTZ NOT NULL,
  sth_json     JSONB  NOT NULL              -- §7.1 STH 对象原文(锚定与对外发布用)
);

-- 私有侧参考(不对外发布、不进公开端点):详情记录与承诺 nonce(§4.2)
CREATE TABLE tlog_entry_details (
  leaf_index    BIGINT PRIMARY KEY REFERENCES tlog_entries(leaf_index),
  detail_json   JSONB  NOT NULL,            -- 事件权威详情记录(域分隔 canonical JSON,§4.2)
  commit_nonce  BYTEA  NOT NULL             -- ≥16 字节新鲜随机 nonce;开承诺时随详情一并披露(§4.2)
);

-- append-only 由数据库权限而非应用自觉保证:
-- 应用角色仅 GRANT INSERT/SELECT,REVOKE UPDATE/DELETE;
-- 另加 BEFORE UPDATE OR DELETE 触发器直接 RAISE EXCEPTION 兜底。
```

要点:

- **写路径**:签发/吊销/锁定事务内同步追加日志条目(同一 Postgres 实例,
  同事务提交保证不漏事件,T3 缓解的实现基础);STH 由定时任务按 §8 频率签发。
- **证明计算**:一期直接载入 `[0, treeSize)` 叶哈希内存计算(10^6 叶 ×
  32 B ≈ 32 MB,单机可行);超过该量级再引入子树缓存 —— 属实现优化,
  不改变对外结构。
- **签名密钥**:tlog STH 签名密钥与 status.v1 签名密钥 SHOULD 分离
  (职能不同,轮换周期不同),发布与固定方式相同(§9.6)。

### 14.2 二期与扩展(意见期后另立工单)

- 实现工单:`/api/tlog` 五端点 + 每日锚定 cron(JSON STH 与 C2SP checkpoint
  双表示,§7.4 / §10)+ 全量镜像脚本样例 + §7.5 测试向量值交付;
- COSE Receipt(RFC 9942)与 SCRAPI(draft-ietf-scitt-scrapi)端点包装,
  使 receipt 可互操作地嵌入 COSE 生态;
- **witness cosigning(C2SP tlog-witness,<https://c2sp.org/tlog-witness>;
  revision -02 列入)**:作为与 SCRAPI **并行、互相独立**的 Phase 2 track
  立项——witness 对 checkpoint 联署,把 §10 的独立留存比对从事后审计升级
  为发布时多方背书;§7.4 的 checkpoint 表示即为对接该生态而设;
- 全量镜像的传输格式参考 **C2SP tlog-tiles**(<https://c2sp.org/tlog-tiles>;
  revision -02 列入);
- 更强外部锚定(§10 扩展节);
- 多 witness 计划与公开 witness 名录。

## 15. 零发明自查表

### 15.1 采用对照(结构 → 标准条款)

| 本设计章节 | 结构 | 标准条款 | 采用方式 |
|---|---|---|---|
| §4.2 条目 timestamp 语义 | 收录时间 | RFC 9162 §4.8 | 语义等同(SCT timestamp) |
| §4.3 canonical JSON | JCS | RFC 8785 | 全文采用 |
| §5 Merkle 树 | MTH、0x00/0x01 域分隔、非满树 | RFC 9162 §2.1.1 | **逐字采用** |
| §6.1 包含证明 | PATH 生成 / 验证 | RFC 9162 §2.1.3.1 / §2.1.3.2 | **逐字采用** |
| §6.2 一致性证明 | PROOF 生成 / 验证 | RFC 9162 §2.1.4.1 / §2.1.4.2 | **逐字采用** |
| §7.1 树头字段 | timestamp / treeSize / rootHash(+logId) | RFC 9162 §4.9 / §4.10 / §4.4 | 字段一一对应(例外:§4.4 定义 Log ID 为 OID,本设计用 URL,偏离入 D-1) |
| §7.2 签名算法 | Ed25519 | RFC 8032 | 全文采用 |
| §7.4 checkpoint 并行表示 | C2SP tlog-checkpoint / signed note | <https://c2sp.org/tlog-checkpoint> / <https://c2sp.org/signed-note> | 格式逐字采用;与 JSON STH 的对应关系在 §7.4 规范定义 |
| §8 日志参数 | Base URL / 算法 / 公钥 / MMD / STH 频率 / 关停 | RFC 9162 §4.1 / §4.13 | 参数集一一对应 |
| §9.1–9.4 端点 | get-sth / consistency / proof-by-hash / get-entries | RFC 9162 §5.2 / §5.3 / §5.4 / §5.6 | 语义一一对应,REST/JSON 转写 |
| §9.6 参数发布 | 公钥发现 | SCRAPI 草案 §2.1(`/.well-known/scitt-keys`) | 职能对应,二期并轨 |
| §10 锚定动机 | split-view 须带外检测 | RFC 9162 §11.3 | 结论采用,通道(git)为工程选择 |
| §11 镜像审计 | Monitor 两算法 / Auditing 分工 | RFC 9162 §8.2 / §8.3 | **逐步对应转写** |
| §12 隐私 | 注册不可撤回 ⇒ 最小化;哈希指代敏感载荷 | RFC 9943 §8 / §6.2 | 准则采用 |
| §13 架构角色 | TS / Registration / Policy / Receipt / VDS | RFC 9943 §3 / §5.1 / §5.1.1 / §6.3 / §4 | 映射表逐项标注 |
| 哈希算法 | SHA-256 | RFC 6234;RFC 9162 §10.2.1 注册表 | 全文采用 |
| 时间戳格式 | RFC 3339 | RFC 3339 | 全文采用 |

### 15.2 偏离声明(全部偏离均为载体/裁剪层面,无新密码学结构)

| # | 偏离 | 理由 | 风险评估 |
|---|---|---|---|
| D-1 | **CT-derived checkpoint profile**(§7,revision -02 改称):STH / 证明用 canonical JSON + Ed25519 三元组壳,不用 RFC 9162 的 TLS presentation language 与 `TransItem`;Log ID 取 URL,而非 RFC 9162 §4.4 规定的 OID | 与 RFC 9162 为**算法层对齐、非 wire 兼容**:§5/§6 算法逐字采用,编码自定义并在 §7.2–§7.3 规范定义签名 transcript 与拒绝规则。RFC 9162 本身为 Experimental,浏览器 CT 生态实际只认 RFC 6962 与 Static CT API,不存在可加入的 RFC 9162 wire 生态;协议全线(status.v1)已用同一签名壳,依赖方复用验签代码 | 无密码学影响:被签名的语义内容与 §4.9/§4.10 等同,仅编码不同;profile 行为由 §7.3 拒绝规则与 §7.5 测试向量约束;跨生态互操作由 §7.4 C2SP checkpoint 表示与二期 COSE Receipt 补齐 |
| D-2 | 单条目不带独立 COSE 签名(SCITT Signed Statement 要求 COSE_Sign1);一期 receipt 为 JSON 而非 RFC 9942 COSE Receipt | 唯一 Issuer = 运营者自身,条目真实性由 STH 签名整树承诺;引入 per-entry COSE 签名在一期只增加体积不增加安全性 | 已在 §13 映射表逐项标注;二期实现 RFC 9942/SCRAPI 后消除该偏离 |
| D-3 | 新增 §9.5 `entry?certId=` 便利索引(RFC 9162 无) | CT 生态靠全量扫描,凭证场景有天然主键;该端点只返回索引、不参与信任判定 | 非密码学结构;定位为 RFC 9943 §5.1.4 Adjacent Service |
| D-4 | 无公开提交端点(裁剪 RFC 9162 §5.1 / SCRAPI §2.3) | 日志对象是运营者自身的签发行为,第三方无可注册物 | 以显式 Registration Policy 公开(RFC 9943 §5.1.1),满足策略透明要求 |

## 16. 参考文献

- **RFC 9162** — Certificate Transparency Version 2.0(Experimental). <https://www.rfc-editor.org/rfc/rfc9162>
- **RFC 6962** — Certificate Transparency(浏览器 CT 生态实际运行版本). <https://www.rfc-editor.org/rfc/rfc6962>
- **RFC 9943** — An Architecture for Trustworthy and Transparent Digital Supply Chains (SCITT Architecture). June 2026. <https://www.rfc-editor.org/rfc/rfc9943>
- **RFC 9942** — COSE Receipts. <https://www.rfc-editor.org/rfc/rfc9942>
- **draft-ietf-scitt-scrapi** — SCITT Reference APIs. <https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/>
- **RFC 8785** — JSON Canonicalization Scheme (JCS). <https://www.rfc-editor.org/rfc/rfc8785>
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA). <https://www.rfc-editor.org/rfc/rfc8032>
- **RFC 6234** — US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF). <https://www.rfc-editor.org/rfc/rfc6234>
- **RFC 3339** — Date and Time on the Internet: Timestamps. <https://www.rfc-editor.org/rfc/rfc3339>
- **RFC 2119 / RFC 8174** — Key words for use in RFCs.
- **C2SP tlog-checkpoint** — Transparency Log Checkpoints. <https://c2sp.org/tlog-checkpoint>
- **C2SP signed-note** — Signed Note format. <https://c2sp.org/signed-note>
- **C2SP tlog-witness** — Transparency Log Witness Protocol. <https://c2sp.org/tlog-witness>
- **C2SP tlog-tiles** — Tiled Transparency Logs. <https://c2sp.org/tlog-tiles>
- **Keybase & Stellar** — Keybase 将其 Merkle 根锚定到 Stellar 链(外部广播通道先例,§10). <https://book.keybase.io/docs/server/stellar>
- `jiaozi.status.v1` — Signed Revocation-Freshness Status Credential. `standards/status-v1/SPEC.md`

---

## 附录 A. 公开征求意见投递文案(W3C CCG mailing list / DIF discussions)

> 使用说明:同一正文两处投递;CCG 发 `public-credentials@w3.org`,
> 标题建议 `[Design review] Transparency log for AI-agent credential
> lifecycle events (CT v2 / SCITT aligned)`;DIF 发 GitHub discussions,
> 可原样复用正文。意见期 7 天,截止日期发帖时填入。

Hi all,

We operate Jiaozi Protocol, an open identity and attestation layer for AI
agents (Ed25519 `did:web` documents, short-TTL signed status credentials,
open spec + conformance vectors). We are adding a **transparency log for
credential lifecycle events** — issuance, suspension, reinstatement,
revocation — so that our own issuing service becomes publicly auditable
and cannot equivocate about its history, and we'd like the community's
review before we implement anything.

Design document (RFC-style, with a zero-invention checklist):
`standards/tlog-v1/DESIGN.md` in our public repo.

Key points, deliberately boring:

- **No new cryptography.** The Merkle tree, inclusion proofs, consistency
  proofs and the monitor algorithm are RFC 9162 (Certificate Transparency
  v2) §2.1 and §8.2, adopted verbatim with SHA-256. Roles, registration
  policy and privacy boundaries follow RFC 9943 (SCITT Architecture);
  phase 2 adds RFC 9942 COSE Receipts and SCRAPI endpoints.
- **Log entries are metadata-only**: credential serial number, one of four
  event types, log timestamp, and a SHA-256 content hash of the detail
  record which stays with the issuer. No subject identity, no public keys,
  no free-text reasons — registration is irrevocable, so we minimize
  accordingly (RFC 9943 §8).
- **Read-only public REST API** mirroring the CT v2 client messages
  (get-sth / consistency / proof-by-hash / get-entries), plus a daily
  anchor: the signed tree head is committed every day to a public git
  directory as an out-of-band channel for split-view detection
  (RFC 9162 §11.3).
- **Phase 1 is a single Postgres table** with database-enforced
  append-only semantics; anyone can mirror the full log and act as an
  independent witness — the document includes a step-by-step audit guide.

We would particularly appreciate feedback on: (1) the JSON re-encoding of
the CT v2 signed tree head (semantics preserved, TLS presentation language
replaced by JCS canonical JSON + Ed25519 — declared as deviation D-1);
(2) whether the per-certId lookup endpoint creates any privacy issue we
missed; (3) prior art on git-based STH anchoring.

The comment window is open for 7 days (until YYYY-MM-DD); after that we
will publish an implementation plan and test vectors. All feedback,
including "this duplicates X, use X instead", is very welcome.

Thanks,
Jiaozi Protocol team

---

## 附录 B. 修订说明(Revision History)

### v1.0-design.2 / revision -02(2026-08-25)

**来源与致谢**:本次 12 项修订全部由 **Michael Beddows(Pyramidal)** 于
2026-08-18 在 W3C CCG public-credentials 邮件列表发表的公开评审驱动
(存档:<https://lists.w3.org/Archives/Public/public-credentials/2026Aug/0017.html>),
特此致谢。`jiaozi.attest.v1` / `jiaozi.status.v1` 语义零变更。

| # | 修订 | 落点 |
|---|---|---|
| 1 | 更正 Log ID 错误声明:RFC 9162 §4.4 定义 Log ID 为 OID(-01 版误称"允许多种形态");本设计用 URL 属偏离,归入 D-1 声明 | §7.1、§8 参数表、§15.1 / D-1 |
| 2 | 全文改称 **CT-derived checkpoint profile**:算法层对齐、非 wire 兼容;注明 RFC 9162 为 Experimental,浏览器 CT 生态实际只认 RFC 6962 与 Static CT API | 引言零发明注、§7 引语、§15 D-1、§16 |
| 3 | 新增 checkpoint profile 规范章节:签名 transcript 精确构造、canonicalization、验证方拒绝规则、测试向量结构占位、密钥引导与轮换 | §7.2–§7.3、§7.5–§7.6 |
| 4 | STH 内嵌 `publicKeyMultibase` 降为 informational;验证方 MUST 用 pinned 公钥(log-info + 锚点交叉确认),MUST NOT 以内嵌公钥自证 | §7.1、§7.3、§7.6 |
| 5 | 全量镜像改为推荐验证路径;`entry?certId=` 降级为低量客户端便利端点,写明查询隐私风险,新增 targeted-query 访问日志最小留存的规范性条款 | §9.5、§11 引语、§12.1 |
| 6 | 新增顺序编号隐私考量:如实记录排序/计量信息泄露;号段格式为既有产品面短期不改;tlog 条目内不透明标识符列为未来评估项 | §12.2 |
| 7 | 时间语义拆分:MMD 改为自日志接受起算(对齐 RFC 9162 §4.1);新增 occurrence-to-inclusion latency 独立服务承诺(分解为 occurrence-to-acceptance 24 h + MMD 24 h,含发生时间的承诺方式与外部审计路径);锚定时限推导由 48 h 改写为接受后 48 h / 发生后最坏 72 h | §4.2、§8、§10 |
| 8 | `contentHash` 改为隐藏承诺:域分隔 canonical 详情对象 + ≥128-bit 新鲜 nonce 取哈希;nonce 与私有详情同存、开承诺时披露;参考 schema 补 nonce 存储 | §4.2、§14.1 |
| 9 | git 锚定降级定性为 weak broadcast channel(作者出处,非全局一致性);更正 force-push 可检测性为有条件(须有留存旧 commit 的观察者);独立留存与交叉比对自 SHOULD 升为 MUST(检测模型的规范性组成部分) | §10、§11.3 |
| 10 | 先例定位补正:Go checksum database / Sigstore Rekor 定位为 signed checkpoint 与独立审计先例(非 git 锚定先例);补 Keybase(Stellar 锚定)为外部广播通道先例 | §10、§16 |
| 11 | 在 JSON STH 之外并行发布 C2SP tlog-checkpoint signed-note 表示;规范定义两种表示与同一 tree head 的对应关系;每日锚点双表示提交 | §7.4、§10、§15.1 |
| 12 | Phase 2 路线补充:witness cosigning(C2SP tlog-witness)列为与 SCRAPI 并行的独立 track;全量镜像参考 C2SP tlog-tiles | §14.2、§11 引语 |

### v1.0-design.1 / revision -01(2026-08)

初版公开征求意见稿(CCG / DIF 双渠道投递,意见期 7 天)。
