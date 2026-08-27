# jiaozi.delegation.v1 — 多跳可衰减委托(Holder-Attenuable Delegation)设计文档

**Status:** Design draft for public review(v1.0-design.4,revision -02,2026-08-27)
**Editor:** Jiaozi Protocol(https://www.jiaozi.io)
**Scope:** 仅设计,无实现(工单 R2 闸门:先公开征求意见 7 天,意见期结束后另立实现工单)。
**§6(Invocation)为 revision -02 新增设计面,将随本修订回 CCG 线程公开征求意见。**
**License:** 文本 CC BY 4.0

> **零发明原则(zero-invention principle)**:本设计不引入任何自创密码学结构。
> 委托链、单调收窄(attenuation)、主体对齐(principal alignment)、caveat 继承等
> 语义逐条对齐 **UCAN v1.0**(github.com/ucan-wg/spec,其 Delegation 子规范
> Version 1.0.0)与 **W3C CCG ZCAP(Authorization Capabilities)v0.4.0-draft**
> (w3c-ccg.github.io/zcap-spec)。每一节标注对应标准条款,与标准的偏离在
> §10「零发明自查表」中逐条声明并给出理由。签名壳与序列化沿用协议既有的
> canonical JSON(RFC 8785 语义)+ Ed25519(RFC 8032),与 `jiaozi.status.v1` 同款。

---

## 目录

1. 引言与动机
2. 术语与约定
3. 威胁模型
4. 委托凭证 schema(`jiaozi.delegation.v1`,canonical JSON)
5. 单调收窄铁律的形式化与验证算法
6. Invocation:资源指定与权限行使(-02 新增)
7. 与既有协议的衔接(attest.v1 / status.v1 / requireTrust)
8. 吊销联动:复用 status.v1 的 60 秒新鲜度
9. 零发明对齐与学术依据
10. 零发明自查表(标准对齐与偏离声明)
11. 分阶段实施(一期:单节点、Postgres 一张表;链长 profile 默认 3)
12. 参考文献
附录 A. 公开征求意见投递计划(CCG 回帖 / IETF I-D / zCap v0.5 用例)
修订记录

---

## 1. 引言与动机

JIAOZI Protocol 为 AI Agent 签发可验证身份凭证(`jiaozi.attest.v1` 签发摘要,
含主人自述的行为边界 `behaviorBoundary`),并以 `jiaozi.status.v1` 短 TTL
签名状态凭证(60 秒重签)向依赖方证明凭证的即时状态。SDK 的 `requireTrust`
中间件已实现**单跳**授权判定:校验来访 agent 的 status.v1 新鲜度与签名、
按 trustLevel 分级、要求请求行为 ⊆ `behaviorBoundary.permissions`。

但真实的 agent 协作是**链式**的:

```text
法人(已 KYB)→ 老板 agent → 采购 agent → 支付 agent
```

授权在这条链上必须**只缩不放**:老板 agent 可以把「采购,单笔 ≤ 1 万元」
交给采购 agent,采购 agent 可以把「支付,单笔 ≤ 5 千元」交给支付 agent,
但任何一环都不得把权限放大回去,也不得伪造出一条不存在的授权路径。

这一能力存在学界与标准界公认的缺口:

- **JWT 一族不可衰减(not holder-attenuable)**。JWT 签名后不可变,受托方
  (holder)无法在不重新签发、不打断密码学链的前提下缩减权限再转授。
  arXiv 论文《AIP: Agent Identity Protocol for Verifiable Delegation Across
  MCP and A2A》(Prakash, 2026, arXiv:2603.24775)在综述中对此有明确表述:
  "JWTs are immutable after signing, so a delegatee cannot attenuate
  authority without minting a new token that breaks the cryptographic
  chain";对 OAuth 亦指出 "OAuth provides no holder-side scope attenuation;
  only the authorization server can narrow scopes at issuance time"。
- **DID/VC 生态只有单跳方案**。W3C VC 表达"签发方对主体的断言",没有
  内建的多跳转授语义;能表达委托链的两个方案 —— UCAN 与 ZCAP —— 分别
  停留在社区规范(UCAN v1.0,IPLD/DAG-CBOR 生态)与 W3C CCG 工作项草案
  (ZCAP v0.4.0-draft)阶段,均未进入 W3C/IETF 标准轨道的定稿序列。
  第三方同一结论:DIF Trusted AI Agent WG 的 Delegated Authorization
  Task Force 评估过 zCap、UCAN、GNAP 与多个 OAuth 系方案后认定,具备
  链式委托能力的方案 "basically, zCaps (JSON-based) and UCANs
  (DAG-CBOR-based) are the only ones"(Dmitri Zagidulin,CCG 邮件列表
  2026Apr/0029,核实 2026-08-12)。
- **该领域正在快速收敛,但尚无对口工作组**。2026 年 5–8 月间,W3C CCG
  先后出现 Vouch Protocol CG Report v1.6.2(§9 资源绑定委托链)与 IETF
  个人草案 draft-helixar-hdp-agentic-delegation-01(HDP,代理委托的
  chain-of-custody)两个同域在研方案(逐项对比见 §9.3);HDP 作者在其
  CCG 征评帖的公开问题 #4 中自述 "There is no obvious existing WG for
  agentic delegation provenance"(2026Aug/0002,核实 2026-08-12)——
  这是对 G6 空白的社区第三方佐证:缺的不是探索,是收敛后的标准与归口。
- 本仓库缝隙台账 `docs/interop-gaps.md` G6 已将此缺口立案:
  "多跳可衰减委托(holder-attenuable delegation)无收敛标准"。

JIAOZI 已有单跳原语(attest.v1 的 `behaviorBoundary` + SDK `requireTrust`)。
本设计把它扩展为多跳链:定义委托凭证 `jiaozi.delegation.v1`、单调收窄铁律
的形式化与验证算法、invocation 层的资源指定语义(§6,-02 新增)、与既有
协议的衔接方式,以及**复用 status.v1 60 秒新鲜度的吊销联动**(不新增任何
吊销机制,这是相对 UCAN 的差异化取舍,§8 论证)。

### 1.1 设计目标

- **G1 可追根**:任意一跳的授权都能沿链密码学回溯到根授权
  (已 KYB 法人名下的 attest.v1 行为边界)。
- **G2 只缩不放**:每一跳的权限集合 ⊆ 父级,约束(caveats)只增不减,
  有效期只短不长,资源集只缩不放;违反即整链无效。
- **G3 即时失效**:链上任一环被吊销/锁定,下游全部授权在 ≤ 60 秒内失效,
  复用 status.v1,不引入吊销令牌、吊销列表等新机制。
- **G4 不动存量**:attest.v1 / status.v1 / requireTrust 单跳语义零改动;
  多跳是纯增量扩展(L3 否决区红线)。
- **G5 一期可落地**:单节点、Postgres 一张表可支撑;链长上限属验证方
  策略,一期实现 profile 默认 3(§3 T6、§11)。

### 1.2 非目标

- 不做离线/分区容忍验证(UCAN 的强项):本协议的信任模型以 status.v1
  在线新鲜度为轴心,委托链验证同样要求能取到链上各环的新鲜状态凭证(§8)。
- 不在一期实现策略语言(UCAN Policy Language 的谓词逻辑、jq 选择器):
  一期 permissions 为扁平字符串集合,caveats 为有限的类型化约束(§4.3);
  caveat 表达格式经 `caveatFormat` 字段可插拔(§4.5),Cedar 等强表达
  profile 列为候选评估、无承诺(§11.2)。
- 不实现资源 designation 的凭证化:v1 的 invocation 以 canonical form 的
  URI 指定资源(§6.3);designation 本身升格为能力凭证留未来版本(§6.6)。
- 不做跨签发方联邦(链上所有 agent 均持 JIAOZI 凭证);跨域互认留二期。
- 不重新定义身份层:delegator/delegatee 的身份与密钥绑定完全沿用既有
  DID 文档与凭证体系。

## 2. 术语与约定

**MUST / MUST NOT / SHOULD / SHOULD NOT / MAY** 按 RFC 2119 / RFC 8174 解释。

| 术语 | 定义 | 来源 |
|---|---|---|
| Root authority(根授权) | 委托链第 0 跳:已 KYB 法人名下 agent 的 `jiaozi.attest.v1` 摘要,其 `behaviorBoundary.permissions` 是全链权限的天花板 | 对应 ZCAP "root capability"(§Root Capability);UCAN [Subject] 的资源根 |
| Delegator(委托方) | 在某一跳中签署委托凭证、把自身部分权限**分享**给受托方的一方(-02 措辞更正:委托是共享而非让渡,delegator 不因委托失去自身权限) | 对应 UCAN Delegation `iss`;ZCAP 父凭证的 `controller` |
| Delegatee(受托方) | 在某一跳中接受权限的一方;可作为下一跳的 delegator 继续转授 | 对应 UCAN Delegation `aud`;ZCAP 子凭证的 `controller` |
| Permission(权限) | 一个权限字符串(动词),取值域与 attest.v1 `behaviorBoundary.permissions` 同一词汇表。-02 起由 "Capability" 更名:capability 一词让位给能力安全含义(见下行与 §6.1) | 对应 UCAN [Command](语义);ZCAP `allowedAction` |
| Capability(能力,能力安全义) | 对**一个特定资源**之上若干权限的不可伪造引用——资源指定(designation)与权限(authority)合一。委托凭证不必是 capability(可覆盖多资源),invocation 必须是(§6.1) | object-capability 文献通例(Hardy 1988;SPKI/SDSI RFC 2693) |
| Resource(资源) | 一次 invocation 作用的对象,以 canonical form 的 URI 标识(§6.3) | ZCAP `invocationTarget`;Vouch §9 资源绑定 |
| Invocation(行权/调用) | 行使权限的动作:指定一个具体资源 + 声称一组动作 + 出示支撑授权的委托链(§6);凭证只在 invocation 时出示 | UCAN Invocation;ZCAP §Invocation |
| Attenuation(收窄/衰减) | 沿链约束权限的过程:每跳 MUST 原样重述或缩减,MUST NOT 放大 | UCAN spec §Attenuation("Each direct delegation MUST either directly restate or attenuate (diminish) its capabilities");ZCAP caveat 语义 |
| Caveat(约束) | 附加在委托上的限制条件;子凭证继承全部父级 caveats 并 MAY 新增;单条 caveat 只能否决、不能授予(deny-only 不变量,§4.3) | ZCAP §Caveats("Capabilities inherit the restrictions from all `caveat` properties of their parents, and MAY add new caveats") |
| Delegation chain(委托链) | 有序的委托凭证数组 `chain[1..n]`,`chain[1]` 锚定根授权,`chain[n]` 为叶(实际行事的 agent 所持) | 对应 ZCAP "capability chain";UCAN proof chain |
| Principal alignment(主体对齐) | `chain[i]` 的 delegatee MUST 等于 `chain[i+1]` 的 delegator | UCAN Delegation §Principal Alignment("the `aud` field of every proof MUST match the `iss` field of the UCAN being delegated to") |
| Presentation(出示) | 叶 agent 向依赖方提交的组合:委托链 + 链上各环的 status.v1;出示只发生在 invocation 时刻,是 invocation 的组成部分(§6.1/§7.2) | 本协议既有出示语义的扩展(§7.2) |
| 凭证号(certId) | `JIAOZI-YYYY-NNNNNN`;历史前缀 `JP-` 原样保留,`JJ-` 归一为 `JP-` | `packages/gdid-core`(`formatCertId` / `normalizeCertId`) |

## 3. 威胁模型

被防御的对手是**链上的任意参与者**(包括受托方自身)与网络中间人。
签发方(Jiaozi Protocol 运营方)在本设计中只扮演既有角色(签发 attest.v1、签发
status.v1),不新增权力;对签发方叙事权的约束由透明日志设计
(`standards/tlog-v1/DESIGN.md`)负责,不在本文档重复。

| # | 攻击 | 描述 | 缓解 | 标准依据 |
|---|---|---|---|---|
| T1 | 越权放大(privilege amplification) | 受托方在转授时塞入父级没有的权限,或删除父级 caveats、延长有效期 | 单调收窄铁律(§5):逐跳校验 `grantedPermissions` ⊆ 父级、caveats ⊇ 父级、`expiresAt` ≤ 父级;任一违反整链拒绝 | UCAN spec §Attenuation;ZCAP §Delegated Capability("A verifier MUST ensure that the `allowedAction` field in a delegated zcap is not less restrictive than the parent's";"a delegated zcap's expiration date-time is not less restrictive than its parent capability's") |
| T2 | 链断裂伪造(chain forgery) | 伪造某一跳签名、拼接不相邻的两段链、把别人的委托嫁接到自己名下 | 每跳 Ed25519 签名由 delegator 密钥出具且 MUST 可验;`parentRef` 哈希指针使链条内容可寻址;主体对齐校验拒绝拼接 | UCAN Delegation §Signature Validation、§Principal Alignment;ZCAP §Delegated Capability(`parentCapability` + delegation proof:"A verifier MUST ensure that a delegated zcap was created by a controller of its parent capability") |
| T3 | 吊销不传播(revocation non-propagation) | 上游被吊销后,下游继续拿旧委托行事 | 全链活性检查:出示物 MUST 含链上每一环主体的新鲜 status.v1(TTL 60 秒),任一环非 active 整链拒绝;失效传播上界 = TTL(§8) | 复用 `jiaozi.status.v1` 既有机制;对比 UCAN Revocation 子规范与 ZCAP 吊销存储义务的取舍论证见 §8.2 |
| T4 | 混淆代理(confused deputy) | deputy 被诱使把**自己的**权限用在**他人指定的资源**上——designation 与 authority 分离所致。属 **invocation 层**问题,不是委托链层的攻击(-02 依评审意见重定性;-01 版将其误置为委托层威胁) | invocation MUST 显式指定资源(缺失即拒,fail-closed),验证方只按叶有效授权对该资源判定;"作为参数传递的资源必须以委托形式授予被调用方"规则——完整处理见 §6.5 | Hardy 1988(The Confused Deputy);object-capability 文献通例;UCAN spec §Subject(命名空间不可伪造) |
| T5 | 重放与串挪(replay / splicing across contexts) | 同一委托凭证在非预期上下文重放 | 每跳含 `nonce`;凭证按内容哈希寻址(`parentRef`),同一凭证在不同链位置不可复用;短有效期进一步压缩窗口 | UCAN spec §Nonce(nonce REQUIRED 防重放);ZCAP 短有效期建议(§Delegated Capability,3 个月上限的动机) |
| T6 | 链长攻击(long chain attack) | 超长链拖垮验证方或稀释审计 | 验证方 **SHOULD** 按部署场景设定链长上限(启发式策略,`policy.maxChainLength`),超限拒绝;一期实现 profile 默认 3(-02 由"协议级硬上限 MUST ≤ 3"改为验证方策略,理由见右栏与 §9.1)。真实业务链(几十跳)与 DoS 级(几千跳)的区别在验证方侧显然可判 | ZCAP §Delegated Capability(MUST 限长,SHOULD ≤ 10);评审经验:跨企业委托常见 ~10 跳,过低硬上限是 antipattern(A. Karp 评审意见 2026-08-18,其公开帖 <https://www.linkedin.com/feed/update/urn:li:activity:7492998040958476289/>,链接为评审人自供) |
| T7 | 链尾截断(chain-tail truncation) | 每跳只向后承诺(签名覆盖自身 payload 与指向父跳的 `parentRef`),攻击者取得链副本后删去尾部若干跳,出示的前缀 `chain[1..k]` 逐跳自洽、结构校验可过(HDP I-D §10.4 对同构问题的表述) | 叶绑定(leaf binding):验证方 MUST 校验本次请求经单跳门认证的出示方 == `chain[n].delegatee`(§5.2 第 4 步);由单调收窄铁律,任何前缀只对其合法叶主体可用,截断不产生权限提升——分析见 §5.3 | UCAN Invocation §Proof Chains(证明链 MUST 终止于 invoker:"ending at the invoker (`iss`)");ZCAP §Invocation(invocation MUST 携带由被调用叶凭证 controller 签署的 `capabilityInvocation` proof) |

**明确不在模型内**:私钥被盗(密钥管理问题,由吊销联动兜底止血)、
签发方作恶(tlog 设计负责)、量子对手、行为层面的越轨监测(运营期工单)。

## 4. 委托凭证 schema(`jiaozi.delegation.v1`)

### 4.1 签名壳(与 status.v1 同款)

一份委托凭证是一个三元组对象,签名壳与 `jiaozi.status.v1` 完全同构,
依赖方可复用同一验签代码路径:

```json
{
  "payload": { "schema": "jiaozi.delegation.v1", "…": "…" },
  "signature": "<base64url Ed25519 signature over canonicalJson(payload)>",
  "publicKeyMultibase": "z6Mk…"
}
```

- 签名算法:**Ed25519(RFC 8032)**;签名对象为 `canonicalJson(payload)`
  的 UTF-8 字节。canonical 规则采用 **RFC 8785(JCS)** 语义,与
  `packages/gdid-core` 现有 `canonicalJson()` 在本 schema 字段域上
  产出逐字节一致的结果(同 tlog 设计 §4.3 的论证)。
- `publicKeyMultibase` MUST 属于 `payload.delegator` 所指主体
  (经其 DID 文档 `verificationMethod` 或凭证登记的 ownerPubkey 绑定,§5.2)。
- **偏离声明**:UCAN 用 DAG-CBOR/IPLD envelope,ZCAP 用 JSON-LD +
  Data Integrity proof;本设计沿用协议既有 JSON 壳。字段语义一一对应、
  收窄与链校验算法不变,仅序列化载体不同(§10 D-1)。

### 4.2 payload 字段

字段全集如下,**不允许列表之外的字段**(标注 MAY 的字段可缺席):

```json
{
  "schema": "jiaozi.delegation.v1",
  "rootCertId": "JIAOZI-2026-000123",
  "parentRef": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "parentLocation": "https://www.jiaozi.io/api/delegations/sha256:9f86d081…",
  "delegator": "JIAOZI-2026-000123",
  "delegatee": "JIAOZI-2026-000456",
  "grantedPermissions": ["procure", "pay"],
  "caveatFormat": "jiaozi.caveats.v1",
  "caveats": [
    { "type": "maxAmountPerTx", "currency": "CNY", "value": 10000 },
    { "type": "allowedResources", "values": ["https://api.example.com/orders"] }
  ],
  "issuedAt": "2026-08-10T12:00:00.000Z",
  "expiresAt": "2026-08-17T12:00:00.000Z",
  "nonce": "8k3O2nH5vXw"
}
```

| 字段 | 类型 | 必填 | 语义 | 标准对应 |
|---|---|---|---|---|
| `schema` | string | MUST | 字面量 `"jiaozi.delegation.v1"` | UCAN envelope tag(`ucan/dlg@1.0.0`)的职能对应物 |
| `rootCertId` | string | MUST | 根授权(第 0 跳 attest.v1)持有者的凭证号;全链所有凭证的 `rootCertId` MUST 相同。**保留的设计理由(-02 补写)**:该值可沿 `parentRef` 走到链头推导,但去范式化保留换来 O(1) 追责定位、登记表检索索引(§11.1)与逐跳早期一致性失败(`chain_root_mismatch`)——验证方无需先走完整链即可拒绝错链拼接 | 对应 UCAN `sub`(Subject:"Principal that the chain is about";本设计不允许 `sub: null` 的 Powerline 模式,见 §10 D-5) |
| `parentRef` | string | MUST | `"sha256:" + 64 hex`。第 1 跳:对根 attest.v1 摘要 canonical JSON 的 SHA-256;第 i>1 跳:对 `chain[i-1].payload` canonical JSON 的 SHA-256 | 对应 ZCAP `parentCapability`(以 ID 引用父凭证);哈希内容寻址与 UCAN 以 CID 链接 proof 的做法同精神(UCAN spec §Token Resolution) |
| `parentLocation` | string | MAY | 父凭证的检索提示(如登记表 URL,-02 依评审意见新增)。**验证 MUST NOT 依赖此字段**:链整链随请求出示(§7.2),验证按 `parentRef` 哈希闭环;本字段仅供链组装方与审计方检索便利 | ZCAP 以 ID(可解引用 URL)引用父凭证的"定位"职能对应物;本设计将定位与完整性锚(哈希)分离 |
| `delegator` | string | MUST | 委托方标识:凭证号(推荐)或 DID。签名密钥归属方 | UCAN `iss`("Every UCAN MUST be signed with the private key associated with the DID in the `iss` field");ZCAP 父凭证 `controller` |
| `delegatee` | string | MUST | 受托方标识:凭证号(推荐)或 DID | UCAN `aud`;ZCAP 子凭证 `controller` |
| `grantedPermissions` | string[] | MUST | 本跳授予的权限集合;非空;词汇表 = attest.v1 `behaviorBoundary.permissions` 的取值域;去重、精确字符串匹配(一期无层级语义,§10 D-2)。(-02 由 `grantedCapabilities` 更名,见修订记录) | UCAN capability(`cmd`)/ZCAP `allowedAction` 的职能对应物 |
| `caveatFormat` | string | MAY | caveats 的表达格式标识(-02 新增,§4.5);缺席等价于 `"jiaozi.caveats.v1"`(§4.3 内置类型注册表)。同一链上所有跳 MUST 一致;验证方遇到未实现的格式 MUST 拒绝整链(fail-closed) | 可插拔格式位;准入条件见 §4.5 |
| `caveats` | object[] | MUST(可为空数组) | 约束对象数组;内置格式下每个对象 MUST 含 `type` 字段;子凭证 MUST 完整继承父级全部 caveats(按 canonical JSON 字节等值判定)并 MAY 追加 | ZCAP §Caveats(继承 + 只增);macaroons caveat 概念(Birgisson et al. 2014) |
| `issuedAt` | string | MUST | RFC 3339 UTC 毫秒精度,签署时间 | — |
| `expiresAt` | string | MUST | RFC 3339 UTC 毫秒精度;MUST > `issuedAt`;第 i>1 跳 MUST ≤ 父级 `expiresAt` | UCAN §Time Bounds(链有效期 = 最晚 nbf 与最早 exp 之间;UCAN 允许 `exp: null`,本设计不允许,见 §10 D-4);ZCAP(`expires` 子级不得比父级宽松;并建议不超过 3 个月) |
| `nonce` | string | MUST | base64url 随机值(≥ 8 字节熵),防重放与同料重签碰撞 | UCAN spec §Nonce(REQUIRED) |

### 4.3 一期 caveat 类型注册表(内置格式 `jiaozi.caveats.v1`)

caveats 语义由验证方执行,**验证方遇到不认识的 caveat 类型 MUST 拒绝整链**
(fail-closed;比 UCAN 的"与本次调用无关的条件可忽略"更严,见 §10 D-3)。
一期注册以下类型,新增类型 MUST 走本文档修订流程:

| `type` | 附加字段 | 语义 |
|---|---|---|
| `maxAmountPerTx` | `currency`(ISO 4217), `value`(number) | 单笔操作金额上限 |
| `allowedAudience` | `values`(string[]) | 仅可对列表内的依赖方(certId/DID)出示 |
| `allowedResources` | `values`(string[],每项为 §6.3 canonical form 的资源标识) | 资源收窄(-02 新增):invocation 的 `resource` MUST 命中 `values`;链上多跳各带一条时逐条评估等价于交集语义——资源集沿链只缩不放(§5.1 第 (4) 条) |
| `timeWindow` | `notBefore`, `notAfter`(RFC 3339) | 在 `expiresAt` 之内进一步限定可用时段 |
| `note` | `text`(string) | 无执行语义的委托事由说明(审计用;对齐 AIP 的 "Context required" 实践:每次委托应说明存在理由) |

**caveat 安全不变量(deny-only,-02 显式写死)**:`jiaozi.caveats.v1`
词汇表中每个 caveat 类型的语义 MUST 是**纯限制性**的——单条 caveat 的
评估只能**否决**本次 invocation,MUST NOT 授予或扩大任何权限;各条 caveat
在验证时逐条合取(§5.2 第 4 步)。deny-only + 合取意味着**追加 caveat
不可能扩权**,这是 grow-only 收窄语义(§5.1)安全性的结构前提。新类型
经修订流程准入时 MUST 论证满足 deny-only;对表达力更强的 caveat 格式,
同一要求以 profile 准入条件的形式出现(§4.5)。

### 4.4 与 behaviorBoundary 的词汇表关系

`grantedPermissions` 不引入新词汇:它与 attest.v1
`behaviorBoundary.permissions` 共用同一自由字符串词汇表(如 `read` /
`write` / `procure` / `pay`),含义由根授权申领时的行为边界声明界定。
第 1 跳的 `grantedPermissions` MUST ⊆ 根 attest.v1 的
`behaviorBoundary.permissions` —— 行为边界就是链的天花板,这正是
"根授权 = attest.v1 的 behaviorBoundary(链的第 0 跳)"的含义(§7.1)。

### 4.5 caveat 表达格式的可插拔位:`caveatFormat`(-02 新增)

一期内置键值 caveat(§4.3)覆盖简单场景,但 caveat 的**语义子集判定**
是真实难题(§5.1 取舍段):复杂策略需要能证明"一条策略是另一条的
子集"的形式化语言。-02 起 schema 预留 `caveatFormat` 字段作为格式
可插拔位:

- 缺席或取值 `"jiaozi.caveats.v1"`:即 §4.3 内置类型注册表,
  deny-only 不变量结构性成立;
- 其他取值:留给未来注册的 caveat 格式 profile。**候选评估中:Cedar**
  (形式化方法背书,可机证策略子集关系;评审人推荐)——仅列为候选,
  **无承诺**;
- 验证方遇到未实现的 `caveatFormat` MUST 拒绝整链(fail-closed,与
  §4.3 未知类型同基调,拒绝码 `unknown_caveat_format`);同一链上各跳
  的 `caveatFormat` MUST 一致,混合格式链 MUST 拒绝。

**profile 准入条件(安全注记,-02 依评审警告写死)**:表达力更强的
格式里,"追加一条 caveat"未必只收不放——为收窄某一维度而新增的属性,
可能在另一维度**扩权**。因此任何 caveat 格式 profile 的准入条件是:
**可证明追加 caveat 不扩权**——对任意 caveat 集 V 与任意新条目 c,
`authorized(V ∪ {c}) ⊆ authorized(V)` 必须成立且可机器检验。内置键值
格式以 deny-only + 合取结构性满足该条件;Cedar 列为候选正因其形式化
工具链有能力对此类性质给出证明。不满足该条件的格式 MUST NOT 注册。

## 5. 单调收窄铁律的形式化与验证算法

### 5.1 形式化

记根授权(第 0 跳)的权限集合
`C₀ = set(rootAttest.behaviorBoundary.permissions)`,约束集合 `V₀ = ∅`,
时间上界 `E₀ = +∞`(根 attest 摘要本身无有效期字段,其活性由 status.v1
新鲜度约束,见 §8);记第 i 跳(`1 ≤ i ≤ n`)委托凭证的
`Cᵢ = set(grantedPermissions)`、`Vᵢ = set(caveats)`(元素按 canonical
JSON 字节等值)、`Eᵢ = expiresAt`;另记 `Rᵢ` 为第 i 跳的**有效资源集**:
`V₁..Vᵢ` 中所有 `allowedResources` 条目的 `values`(canonical form,§6.3)
之**交集**;若无任何该类条目,`Rᵢ` = 全集(资源在委托层不受限,但
invocation 层仍 MUST 指定具体资源,§6.2)。

**单调收窄铁律(monotonic attenuation invariant)**,对每个 `i ∈ [1, n]`:

```text
(1) 权限只缩不放:   Cᵢ ⊆ Cᵢ₋₁
(2) 约束只增不减:   Vᵢ ⊇ Vᵢ₋₁
(3) 有效期只短不长: Eᵢ ≤ Eᵢ₋₁
(4) 资源只缩不放:   Rᵢ ⊆ Rᵢ₋₁
```

第 (4) 条由 (2)(caveats 只增)与 `allowedResources` 的交集语义**蕴含**,
但 -02 起把它从"实现推论"升格为**显式协议承诺**写死(依外部压测意见):
任何未来的 caveat 格式 profile 或验证器实现 MUST 保持资源维度单调收窄,
不得因表达格式演化而回退。

四条合起来等价于:链上每个主体的**有效授权**
`effective(i) = (Cᵢ, Vᵢ, Eᵢ, Rᵢ)` 沿链构成偏序意义上的单调递减序列;
叶主体的有效授权即 `effective(n)`,不需要(也不允许)对链取交集之外的
任何"合并"运算。此不变式与 UCAN spec §Attenuation("MUST either directly
restate or attenuate")、ZCAP 对 `allowedAction`/`expires`/`caveat`
的三条 verifier MUST 规则,以及 draft-prakash-aip-00 §3.3
("At each delegation step, scope can only narrow or remain equal, never
widen … Verifiers MUST check attenuation at every hop in the delegation
chain")语义一致。

一并明确两条推论(验证方不得依赖直觉之外的行为):

- **无放大合并**:若某主体同时持有多条链,各链授权独立评估,MUST NOT
  跨链求并集(UCAN 的 authority union 语义不适用于本设计,见 §10 D-6)。
- **通配符禁止**:一期权限为精确字符串,无 `*`/前缀语义;父级不含某权限
  字符串,子级即不可含(对比 draft-prakash-aip-00 §3.3 的通配符规则:
  "a specific value in the parent MUST NOT widen to a wildcard in the
  child"——本设计干脆不设通配符,见 §10 D-2)。

**取舍声明(-02 补写,回应评审对 caveat 子集判定难度的意见)**:本设计
**有意回避** caveat 的语义子集比较。铁律 (2) 要求子凭证逐字继承父级全部
caveats(canonical JSON 字节等值)且只许**追加**,不允许"改写式收窄"
(如把 `maxAmountPerTx` 的 10000 改写成 5000——正确做法是追加一条 5000
的新条目,合取评估自然取更严者)。权限维度的子集判定平凡(字符串集合
包含);caveat 维度以 **grow-only + 逐条合取**换取判定平凡性,代价是
caveat 集合沿链只增不减、无法合并化简。语义比较器(证明一条策略是另一
条的子集)留给未来 caveat 格式 profile 评估(§4.5)。

### 5.2 验证算法(伪码,从叶到根)

输入:委托链 `chain[1..n]`(叶为 `chain[n]`)、根授权摘要 `rootAttest`
(`jiaozi.attest.v1`)、链上各主体的新鲜 status.v1 集合 `statuses`、
出示方 `presenter`(本次请求经既有单跳门认证的叶 agent 凭证号,
即其 `statusCredential` 的 certId,§7.2/§7.3)、本次请求的 invocation
对象 `request = { resource, actions, context }`(§6.2;`actions` 即
-01 版的 `behaviors`,更名随术语纪律,语义不变)、验证方策略
`policy = { maxChainLength, now }`(`maxChainLength` 为验证方启发式,
一期 profile 默认 3,T6)。输出:放行/拒绝(带原因码)。

```text
VerifyDelegationChain(chain[1..n], rootAttest, statuses, presenter, request, policy):

  ## 第 0 步:结构、链长与 caveat 格式(T6)
  if n == 0 or n > policy.maxChainLength:
      return DENY(chain_too_long)                      # 上限为验证方策略(SHOULD 设定),
                                                       # 一期 profile 默认 3
  for i in 1..n:
      if chain[i].payload.schema != "jiaozi.delegation.v1" or 字段不合 §4.2:
          return DENY(invalid_delegation)
      f := chain[i].payload.caveatFormat ?? "jiaozi.caveats.v1"
      if f 未被验证方实现 or f != (chain[1].payload.caveatFormat ?? "jiaozi.caveats.v1"):
          return DENY(unknown_caveat_format)           # fail-closed;全链格式须一致(§4.5)

  ## 第 1 步:从叶到根,逐跳校验签名、链接与收窄(T1、T2)
  for i = n downto 1:
      p  := chain[i].payload
      pk := resolveKey(p.delegator)                    # DID 文档 verificationMethod
                                                       # 或凭证登记 ownerPubkey
      if chain[i].publicKeyMultibase != pk:            # 密钥归属绑定
          return DENY(chain_key_mismatch)
      if not Ed25519.verify(pk, canonicalJson(p), chain[i].signature):
          return DENY(chain_signature_invalid)         # UCAN §Signature Validation
      if policy.now >= p.expiresAt:
          return DENY(chain_expired)                   # UCAN §Time Bounds
      if p.rootCertId != rootAttest 持有者凭证号:
          return DENY(chain_root_mismatch)

      if i > 1:
          q := chain[i-1].payload                      # 父跳
          if p.parentRef != sha256(canonicalJson(q)):
              return DENY(broken_chain)                # ZCAP parentCapability
          if p.delegator != q.delegatee:
              return DENY(principal_misalignment)      # UCAN §Principal Alignment
          if not set(p.grantedPermissions) ⊆ set(q.grantedPermissions):
              return DENY(attenuation_violation)       # 铁律 (1)
          if not set(p.caveats) ⊇ set(q.caveats):      # canonical JSON 字节等值
              return DENY(attenuation_violation)       # 铁律 (2);(4) 随交集语义被蕴含
          if p.expiresAt > q.expiresAt:
              return DENY(attenuation_violation)       # 铁律 (3)

  ## 第 2 步:锚定根授权(第 0 跳,T2)
  first := chain[1].payload
  if first.parentRef != sha256(canonicalJson(rootAttest)):
      return DENY(chain_root_mismatch)
  if first.delegator != rootAttest 持有者凭证号:
      return DENY(chain_root_mismatch)
  if not set(first.grantedPermissions)
         ⊆ set(rootAttest.behaviorBoundary.permissions):
      return DENY(attenuation_violation)               # 行为边界 = 天花板

  ## 第 3 步:全链活性(T3,细节见 §8)
  for subject in { first.delegator } ∪ { chain[i].payload.delegatee, i=1..n }:
      s := statuses[subject]
      if s 缺失 or not verifyStatusCredential(s).valid: # gdid-core 既有验签
          return DENY(chain_status_missing)
      if s.payload.status == "revoked":   return DENY(chain_revoked)
      if s.payload.status == "suspended": return DENY(chain_suspended)
      if s.payload.status != "active":    return DENY(chain_status_missing)

  ## 第 4 步:叶绑定与 invocation 判定(T7、T4;invocation 对象见 §6.2)
  leaf := chain[n].payload
  if presenter != leaf.delegatee:                    # 叶绑定,防链尾截断(§5.3)
      return DENY(chain_leaf_mismatch)               # UCAN Invocation §Proof Chains;
                                                     # ZCAP §Invocation(capabilityInvocation)
  if request.resource 缺失或为空:
      return DENY(resource_missing)                  # 资源指定 MUST,fail-closed(§6.2)
  r := canonicalizeResource(request.resource)        # RFC 3986 规范化(§6.3)
  if not set(request.actions) ⊆ set(leaf.grantedPermissions):
      return DENY(behavior_out_of_boundary)
  for caveat in leaf.caveats:
      if caveat.type 不在验证方已注册类型表:
          return DENY(unknown_caveat)                  # fail-closed,§4.3
      if not evaluate(caveat, r, request.context):     # allowedResources 在此评估:
          return DENY(caveat_violation)                #   r ∈ caveat.values(§4.3;§5.1 (4))

  return ALLOW(effective = leaf, resource = r)
```

复杂度:`O(n)` 次验签 + `O(n·|C|)` 次集合包含判定;一期 profile 默认
`n ≤ 3`,单次判定在个位毫秒量级(参照 AIP 论文对 depth 5 链
sub-millisecond 验证的测量,arXiv:2603.24775 §abstract)。

### 5.3 链尾截断(T7):叶绑定即足够

本设计每跳签名只向后承诺(签名覆盖自身 payload,其中 `parentRef` 哈希
指向父跳),不向前承诺后继,因此删去尾部若干跳得到的前缀 `chain[1..k]`
逐跳自洽,能通过 §5.2 第 0–3 步的全部结构、签名与活性检查(删头与删
中间跳则分别被第 2 步根锚定与第 1 步 `parentRef`/主体对齐检查拒绝)。
此问题形态由同域方案 HDP 首先公开分析(其 I-D §10.4:删尾后的 token
"still passes every step of the verification pipeline";本节最初为回应
其 CCG 征评帖公开问题 #2 而写,-02 依评审意见精简篇幅,结论不变)。

对策是 §5.2 第 4 步的**叶绑定(leaf binding),不引入链长承诺**:验证方
MUST 校验本次请求经既有单跳门认证的出示方 `presenter` 等于
`chain[n].delegatee`——链必须精确终止于本次请求的行事主体,不多一跳、
不少一跳。这不是新发明:UCAN Invocation §Proof Chains 要求证明链
"MUST form a direct line of authority … ending at the invoker (`iss`)";
ZCAP §Invocation 要求 invocation 携带由被调用叶凭证 controller 签署的
`capabilityInvocation` proof。本协议中出示方身份由既有单跳门建立
(叶 agent 的 statusCredential,§7.3 判定顺序),叶绑定只是一次等值
比对,零新增机制。

**为何足够**:本设计的链是**授权物**且受单调收窄铁律约束——前缀
`chain[1..k]` 的叶授权 `effective(k)` 恰好就是 `chain[k].delegatee`
本来合法持有的授权。叶绑定生效后,截断者出示前缀的唯一出路是自己就是
`chain[k].delegatee`,而那只是行使自己本有的权限;冒充他人则在叶绑定处
被拒。**截断不构成权限提升,故无需签名链长承诺。** HDP 的 token 是
**取证物**(evidence trail,其 §10.1 自述),验证不要求出示方证明自己
是链尾主体,删尾即隐匿转手记录,属审计完整性问题,只能求助带外完整性
检查——两者问题同构、风险性质不同。"某主体又向下转授过哪些跳"的完整
历史不是授权判定的输入,本设计不在授权层承诺审计完整性;该需求由
§11.1 的可选登记表与透明日志(tlog)带外通道承接,与 HDP §10.4 建议的
out-of-band completeness checks 分工一致。

## 6. Invocation:资源指定与权限行使(-02 新增)

> 本章为 revision -02 新增设计面(回应评审意见:invocation 是"坑最多的
> 地方",-01 只规范了出示物而未把 invocation 规范为对象),将随本修订
> 回 CCG 线程公开征求意见后再进入实现评估。

### 6.1 三个概念:delegation / capability / invocation

-02 采纳评审给出的概念框架,三者严格区分:

- **Delegation(委托)**:权限的分享与收窄。一条委托可以覆盖多个资源
  (乃至不显式限定资源),它**不必**是能力安全意义上的 capability;
- **Capability(能力)**:对**一个特定资源**之上若干权限的不可伪造
  引用——资源指定(designation)与权限(authority)合一(SPKI/SDSI
  与 object-capability 文献的经典含义,§2 术语表);
- **Invocation(行权)**:行使权限的那一步。**invocation MUST 是
  capability 性质的出示**:指定一个具体资源、声称一组动作、出示支撑
  授权的委托链;delegation 则不必。

这正是 §4.2 payload 不设一等 `resource` 字段的原因:资源 designation
的职责在本章(invocation 对象),链上资源**收窄**由 `allowedResources`
caveat 承担(§4.3)——designation 与 caveats 是两类东西,不混入同一
集合(分离的动机另见 §6.6)。这一框架同时解释 §7.2 的出示语义:
**凭证只在 invocation 时出示**,presentation 是 invocation 的组成部分,
不是独立动作。

### 6.2 invocation 对象

一次 invocation 在验证方处评估为如下对象:

```json
{
  "resource": "https://api.example.com/orders",
  "actions": ["procure"],
  "context": { "amount": 4200, "currency": "CNY" }
}
```

| 字段 | 类型 | 必填 | 语义 |
|---|---|---|---|
| `resource` | string | **MUST** | 本次行权作用的资源,canonical form(§6.3)。**缺失即拒**(`resource_missing`,fail-closed):资源**收窄**(`allowedResources` caveat)是可选的,资源**指定**不是——本协议不存在"未指明资源的行权" |
| `actions` | string[] | MUST | 声称的动作集,非空;词汇表同 `grantedPermissions`(§4.4);MUST ⊆ 叶凭证 `grantedPermissions` |
| `context` | object | MAY | 供 caveat 评估的上下文(金额、时段等,§4.3) |

**载体与来源认证**:v1 的 invocation 对象随既有请求通道提交(§7.3
传输层),**不新增独立签名壳**;其来源认证 = 既有单跳门(叶 agent 的
status.v1)+ 叶绑定(§5.2 第 4 步)。ZCAP 对 invocation 的
`capabilityInvocation` proof 义务,在本协议中由"单跳门认证出的
presenter == 叶 delegatee"的等值检查承载(偏离声明见 §10 D-9)。

**范围界定(G4)**:本章约束**委托链参与判定**的 invocation;单跳路径
(无 `delegationChain`)行为零变化——其"资源即验证方自身"的既有隐含
语义保持不变,requireTrust 单跳语义不动(L3 红线)。

### 6.3 资源标识与 canonical form

资源比较若对字符串变体敏感,收窄即可被绕过:大小写、尾斜杠、百分号
编码、默认端口等变体指向同一资源却逃过精确匹配。v1 规定规范化规则
(-02 依外部压测意见埋地基:现在不定,将来追加即破坏性变更):

- `resource` 与 `allowedResources.values` 的每一项 MUST 为 RFC 3986 URI;
- 比较前 MUST 施加 RFC 3986 §6.2.2 基于语法的规范化(scheme 与 host
  小写;百分号编码十六进制大写、非保留字符解码;路径点段消除)与
  §6.2.3 基于 scheme 的规范化(移除默认端口;空路径归一为 `/`);
- 规范化之后做**精确字符串比较**——与 §5.1 的判定平凡性一脉:全部
  歧义收敛在规范化一步,比较本身无歧义、无前缀/通配语义(一期);
- 产出方(委托方写 `allowedResources`、调用方写 `resource`)SHOULD
  直接产出 canonical form,把规范化成本留在写侧。

### 6.4 invocation 验证

invocation 判定完整并入 §5.2 第 4 步,无独立算法:叶绑定 → 资源指定
检查(缺失即拒,`resource_missing`)→ 资源 canonical 化(§6.3)→
`actions` ⊆ 叶 `grantedPermissions` → caveats 逐条合取评估
(`allowedResources` 即在此处以 `resource ∈ values` 评估;多跳各带一条
时逐条评估等价于交集,§5.1 第 (4) 条)。新增拒绝码 `resource_missing`
与 `unknown_caveat_format` 并入 §7.3 拒绝码表。

### 6.5 混淆代理(T4)与"资源参数必须委托"规则

经典混淆代理(Hardy 1988)是 **designation 问题**:deputy 把**自己的**
权限用在**他人指定的资源**上——权限(authority)与资源指定
(designation)走了两条通道,才给了攻击者"用别人的权限、指自己想指的
资源"的空隙。它属于 invocation 层,不是委托链层的攻击(-01 版将其列为
委托层威胁并声称由逐跳显式授权缓解,系误置;-02 依评审意见重定性,
§3 T4 已同步改述)。

缓解 = designation 与 authority 同行:

- invocation MUST 显式指定资源(§6.2),验证方只按**叶有效授权**
  (`grantedPermissions` × 资源集 `Rₙ`,§5.1)对**该资源**判定;不存在
  "deputy 自身权限更大就代为放行"的通道;
- **资源参数规则(能力安全通例,-02 收录)**:调用中**作为参数传递的
  资源 MUST 以委托的形式授予被调用方**,而不是只传资源名、让被调用方
  用自己既有的(可能更宽的)权限去访问。即:agent A 请 agent B 对资源
  X 行事时,A MUST 随请求出具一条收窄到 X 的委托(B 为 delegatee),
  B 对 X 的访问凭**这条链**走本协议 invocation 验证——B 自己的宽权限
  不得代位。deputy 手中没有可替他人行使的 ambient 权限,混淆即无从
  发生。

### 6.6 前瞻:designation 的凭证化(v1 不实现)

本设计把资源指定与 caveats 严格分开(designation 是 invocation 对象的
一等字段 + 专用 caveat 类型,不混入一般约束语义),一个动机是为未来留
升级空间:资源 designation 本身可以(或许应当)是一张**能力凭证**
(capability certificate)——如 SPKI/SDSI(RFC 2693)与 KYA-OS 以
证书/VC 做 capability 的用法——届时 `resource` 字段由 URI 升格为凭证
引用,designation 的不可伪造性由密码学承载而非命名约定。v1 不实现
凭证化 designation;payload 一等 `resource` 字段亦不引入,两者留 v2 与
ZCAP(`invocationTarget`)桥接时一并评估(§11.2)。

## 7. 与既有协议的衔接

### 7.1 根授权 = attest.v1 的 behaviorBoundary(链的第 0 跳)

- 链的信任根不是一个自签对象,而是**签发方已核验并登记的
  `jiaozi.attest.v1` 摘要**:其 `ownerPubkey` 绑定根主体密钥,其
  `behaviorBoundary.permissions` 即 `C₀`。
- 与 ZCAP 的差别:ZCAP root capability 由资源控制者自持自证
  ("Authority starts with the target"),本设计的根多一层机构核验
  (KYB 法人 → 凭证登记),把"链能追责到某个真实法人"变成协议性质
  而非应用约定(§10 D-7)。收件箱既有的 orgRef 设计(attest.v1 可选
  扩展位写入背书法人标识,可关联 GLEIF LEI)与本设计正交且互补:
  orgRef 落地后,根锚定自动获得法人级标识,本文档无需改动。
- **根锚定的语义是问责,不是资源所有权(-02 明示)**:本设计的根回答
  "这条链最终能追责到哪个真实法人",**不**断言根主体拥有链上行权所及
  的资源——资源指定与判定在 invocation 层(§6)。因此"agent(非 KYB
  法人)自建资源并对外委托访问"的场景 v1 明确不覆盖(out of scope):
  该场景的信任根是资源本身的控制权,与本协议"KYB 法人问责链"的产品域
  取舍不同;需要它的部署应直接采用 ZCAP 的自持根模型,或待本协议后续
  版本评估。
- attest.v1 与 behaviorBoundary 的既有语义**零改动**(L3 红线):
  委托链只是读取 `behaviorBoundary.permissions` 作为天花板,
  不要求也不修改其签发流程。

### 7.2 出示物:委托链 + 每环的 status.v1

叶 agent 向依赖方出示的完整材料(presentation)——出示发生在且仅在
invocation 时刻,是 invocation 的组成部分(§6.1):

```json
{
  "delegationChain": [ { "payload": {}, "signature": "", "publicKeyMultibase": "" } ],
  "chainStatus": {
    "JIAOZI-2026-000123": { "payload": {}, "signature": "", "publicKeyMultibase": "" },
    "JIAOZI-2026-000456": { "payload": {}, "signature": "", "publicKeyMultibase": "" }
  },
  "statusCredential": { "payload": {}, "signature": "", "publicKeyMultibase": "" }
}
```

- `statusCredential`:叶 agent 自己的 status.v1(与现行单跳出示完全一致);
- `delegationChain`:§4 凭证的有序数组(`chain[1]` 在前);
- `chainStatus`:链上**其余**各主体(根持有者与中间各 delegatee)的
  status.v1,键为凭证号。status.v1 TTL 60 秒,叶 agent 在发起请求前
  拉取即可;依赖方也 MAY 自行向公开 status 端点取数替代(在线场景等价)。

与 ZCAP 的呈现义务一致:"all delegated zcaps in a chain must be fully
provided to the verifier when invoking a delegated zcap"(ZCAP
§Delegated Capability)——链必须整链随请求出示,验证方无需解引用
(`parentLocation` 仅为组装/审计便利,§4.2)。

### 7.3 requireTrust 的多跳扩展接口草案(不改单跳语义)

以下为二期实现工单的接口草案(**本工单不写代码**)。原则:
`delegationChain` 缺席时,行为与现行 `requireTrust` 逐字节一致。

```ts
// —— 接口草案(design only,非交付代码)——
type TrustPresentation = {
  statusCredential?: unknown;            // 既有字段,语义不变
  behaviorBoundary?: BehaviorBoundaryV1; // 既有字段,语义不变
  delegationChain?: unknown[];           // 新增:jiaozi.delegation.v1 有序数组
  chainStatus?: Record<string, unknown>; // 新增:链上其余主体的 status.v1
};

type RequireTrustOptions = {
  minLevel?: RequirableTrustLevel;       // 既有
  behaviors?: string[];                  // 既有;委托路径下即 invocation 的 actions(§6.2)
  verify?: { /* 既有透传 */ };
  delegation?: {                         // 新增,可选
    enabled?: boolean;                   // 默认 false:不启用则忽略 delegationChain
    maxChainLength?: number;             // 默认 3(一期 profile 默认;上限属验证方策略,T6)
    rootAttest?: unknown | ((rootCertId: string) => Promise<unknown>);
                                         // 根 attest.v1 摘要或解析器
    resource?: string | ((req: unknown) => string);
                                         // 新增(-02):invocation 资源标识(§6.2);
                                         // 缺省实现 SHOULD 从请求目标 URL 导出
                                         // canonical form(§6.3);导不出且未配置
                                         // → resource_missing 拒绝(fail-closed)
  };
};

// 新增拒绝码(TrustDenyCode 的并集扩展,既有码不变):
//   "chain_too_long" | "invalid_delegation" | "chain_key_mismatch" |
//   "chain_signature_invalid" | "chain_expired" | "broken_chain" |
//   "principal_misalignment" | "attenuation_violation" |
//   "chain_root_mismatch" | "chain_leaf_mismatch" | "chain_status_missing" |
//   "chain_revoked" | "chain_suspended" | "unknown_caveat" | "caveat_violation" |
//   "resource_missing" | "unknown_caveat_format"
```

判定顺序:先走既有单跳门(叶 agent 自己的 status.v1 新鲜度、验签、
trustLevel 阶梯),全部通过后,若 `delegation.enabled` 且出示了
`delegationChain`,再执行 §5.2 算法——单跳门认证出的来访主体凭证号
即作为 §5.2 的 `presenter` 输入(叶绑定,防链尾截断,§5.3);invocation
对象按 §6.2 组装:`actions` 取中间件既有 `behaviors` 选项值,`resource`
按上表配置导出(缺失即拒);`behaviors` 的包含关系检查对象由
"叶 agent 自述 behaviorBoundary"切换为"叶委托凭证的
`grantedPermissions`"(链内授权优先于自述边界,二者同时出示时取交集,
fail-closed)。传输层沿用既有双 header 风格,新增
`x-jiaozi-delegation`(链)与 `x-jiaozi-chain-status`(链状态),
编码同 `x-jiaozi-status`(JSON 原文或 base64url)。

### 7.4 attest.v1 扩展位预留登记(`delegation` 容器,R3 签字 2026-08-25)

为委托链落地预留挂点,`jiaozi.attest.v1` 摘要新增**可选**顶层扩展容器
字段 `delegation`(类型=对象;缺席完全合法)。v1 验证器将其视为
**不透明对象**:出现时仅做"是对象"的形状校验(非对象拒绝),不校验
内部结构、不参与签名域之外的任何逻辑判定;attest.v1 载荷整体签名时该
字段自然进入签名域——预留的是结构,不是绕过签名。无该字段的存量凭证
与 SDK 行为零变化,与 G4(不动存量)一致。

初始已知子字段(**仅文档层面登记,运行时不校验**;字段名与语义借用
§4.2 payload 字段表与 §7.3 接口草案,不另造词):

| 子字段(草案) | 语义 |
|---|---|
| `delegator` | 委托方标识:凭证号(推荐)或 DID(§4.2) |
| `grantedPermissions` / `caveats` / `expiresAt` | scope 收缩相关字段(单调收窄铁律维度,§5.1):权限只缩不放、约束只增不减、有效期只短不长 |

(子字段名随 -02 术语更名同步:`grantedCapabilities` →
`grantedPermissions`。该容器 v1 运行时不校验内部结构、无任何实现依赖
此名,更名零行为影响;attest.v1 本体语义不变,见修订记录。)

子字段的运行时校验与链验证算法属二期实现工单(§7.3),不在本预留
范围。落点:`packages/gdid-core`(`AttestSummaryV1.delegation` +
`isAttestSummaryV1` 形状校验)与 `packages/validator`
(`build_summary(delegation=…)`),两侧测试锁定同一组行为。

## 8. 吊销联动:复用 status.v1 的 60 秒新鲜度

### 8.1 机制(-02 改写:显式吊销定性 + 自包含说明 + 策略旋钮 + 可用性兜底)

**吊销是显式动作,TTL 是传播上界。** 签发方把某凭证状态置为
revoked/suspended 是一次显式管理动作;status.v1 的短 TTL 决定的是这一
动作传播到所有验证方的**时间上界**,不是"用超时代替吊销"。

**status.v1 签什么、怎么验(自包含说明,-02 依评审意见补写;规范正文
见 `standards/status-v1/SPEC.md`)**:status.v1 是签发方对单个凭证即时
状态的短时效签名断言。payload 含 `certId`(断言对象)、`status`
(active / suspended / revoked / unknown)、`serial`(每签发方单调递增,
防回滚重放)、`signedAt` / `expiresAt`(TTL 窗口,参考部署 60 秒)、
`issuer` 等字段;**签名对象是 payload 的 canonical JSON(RFC 8785 语义)
UTF-8 字节,算法 Ed25519**——与 §4.1 委托凭证同壳。所谓"每 60 秒重签",
指签发方每个 TTL 周期对**当前状态**重新产出 payload(serial 与时间戳
前进、`status` 取此刻权威值)并重新签名。验证方检查(status.v1 SPEC §7):
形状与 schema 字面量 → 验签 → `now ≤ expiresAt` → serial 不回退(如维护
缓存)→ 而后才消费 `status` 值;任一步失败按 fail-closed 处理。

委托链的活性完全寄生在这套既有机制上,**不新增任何吊销机制**:

- 验证方对链上每个主体(根持有者、每个 delegatee)MUST 见到一份通过
  上述检查且 `status == "active"` 的 status.v1(§5.2 第 3 步);
- 链上任一环被吊销(revoked)或锁定(suspended)后,其旧状态凭证最多
  再存活一个 TTL,之后该主体拿不出合格的新鲜状态凭证 → **下游全部委托
  即时失效,失效传播上界 = 60 秒**;
- `suspended` 是可逆锁定:解锁后无需重建委托链,链自动恢复可用
  (委托凭证本身未失效,只是活性检查暂时不过)——这一"暂停/恢复"
  粒度是吊销令牌类方案没有的。

**新鲜度策略旋钮(-02 新增)**:"60 秒内可造成大量伤害"的批评对高价值
操作成立。TTL 是协议给出的**默认上界**,不是验证方能力的上限:验证方
MAY 按操作价值要求更强的新鲜度——收紧可接受的剩余 TTL(如只认签发后
5 秒内的状态凭证),直至对高价值操作**绕过出示物、直查签发方 status
端点**(残余窗口收敛到网络往返)。该旋钮属验证方策略,协议不设 MUST;
TTL 机制本体不变。

**可用性兜底(-02 新增,回应评审"TTL 签发者失效怎么办"之问)**:status
端点为可用性做**双锚部署**(主锚 + 镜像域名,镜像响应携带 stale-if-error
标注),SDK 支持多锚顺序回退。**镜像是可用性锚,不是第二信任根**:所有
锚点分发的都是同一签发方密钥签出的凭证,镜像自身无签发能力、不能凭空
铸造状态。若签发方全部锚点不可达、任何主体拿不出新鲜状态凭证,验证方
按既有 fail-closed 基调**拒绝**——退化为拒绝服务,不退化为放行,
可用性故障不打开安全豁口(status.v1 SPEC §11 "Blocking the channel"
同一立场)。

### 8.2 为什么这是差异化优势(对比 UCAN)

UCAN 的吊销是独立子规范(UCAN Revocation,总规范中列为 RECOMMENDED
级别),模型是**主动送达的吊销消息**:委托链上的祖先签发吊销令牌,
指向被吊销 UCAN 的内容地址,验证方/执行方需要**收到并存储**这些吊销
记录才能拒绝旧凭证。这是 UCAN 为换取**离线/分区容忍验证**必须付出的
代价:凭证自含、无需回源,则吊销信息只能靠额外通道追着送。
ZCAP 同样要求验证方维护吊销状态存储:"a verifier MUST store revoked
zcaps until they expire, to prevent their use"——并因此建议委托有效期
不超过 3 个月,以限制吊销存储的规模(ZCAP §Delegated Capability)。

本协议的信任模型从第一天起就是**在线新鲜度**(status.v1 60 秒重签,
依赖方永远只认新鲜签名),因此:

| 维度 | UCAN Revocation / ZCAP 吊销 | jiaozi.delegation.v1 |
|---|---|---|
| 新增机制 | 吊销令牌 / 吊销列表 + 送达通道 | **无**(复用 status.v1) |
| 验证方存储 | 需存吊销记录至凭证过期 | 无状态(每次看新鲜凭证) |
| 传播时延 | 取决于送达与轮询,无协议上界 | 协议上界 = TTL(60 秒) |
| 覆盖遗漏 | 未送达的验证方继续放行 | 不存在"未送达":拿不出新鲜状态即拒绝 |
| 可逆暂停 | 无(吊销即终局) | suspended/active 可逆,链自动恢复 |
| 离线验证 | 支持(其设计目标) | **不支持**(诚实声明的取舍,§10 D-8) |

结论:在"agent 高频在线互访"的目标场景里,把吊销归约为新鲜度检查,
换来了零新增机制、无状态验证方和 60 秒硬上界;放弃的离线可验特性
本就不在本协议的信任模型内(status.v1 单跳今天已是如此,多跳只是
保持一致)。

### 8.3 与单跳语义的一致性

单跳 requireTrust 今天对来访 agent 的 revoked/suspended 已经分别给出
`revoked` / `suspended` 拒绝码;多跳扩展将同一判定逐环施加
(`chain_revoked` / `chain_suspended`),无任何新语义。签发方侧
(status.v1 的签发与重签)**零改动**。

## 9. 零发明对齐与学术依据

### 9.1 标准对齐(逐主题)

- **委托链与主体对齐**:UCAN Delegation(Version 1.0.0)§Token
  Validation 三要件(Time Bounds / Principal Alignment / Signature
  Validation)→ 本设计 §5.2 第 1 步逐条对应;ZCAP v0.4.0-draft
  `parentCapability` + delegation proof → `parentRef` + 每跳签名。
- **收窄语义**:UCAN spec §Attenuation;ZCAP 对 `allowedAction` /
  `expires` / `caveat` 的 verifier MUST 三规则;draft-prakash-aip-00
  §3.3(四维收窄:tools/budget/domains/time,verifier 每跳必查)。
- **caveat 只增不减**:ZCAP §Caveats 原文("Capabilities inherit the
  restrictions from all `caveat` properties of their parents, and MAY
  add new caveats in addition to those of their parents");概念源头
  macaroons(Birgisson et al., NDSS 2014)。
- **资源指定与规范化**:ZCAP root capability MUST 具 `invocationTarget`
  URI;资源标识规范化采 RFC 3986 §6.2.2/§6.2.3(→ §6.2/§6.3)。
- **链长上限**:ZCAP §Delegated Capability(MUST 限长,SHOULD ≤ 10)。
  -02 起本设计同取 **SHOULD**:上限是验证方按部署场景执行的启发式
  (T6),3 只保留为一期实现 profile 的默认值——由 -01 的"协议级硬
  上限 MUST ≤ 3"改回。rationale:跨企业委托实践中链长常见 ~10 跳,
  过低的协议级硬上限是 antipattern(评审经验,T6 引注);真实长链与
  DoS 级链长的区分本就该由验证方裁量,这也与 zCap 收尾工作组内
  "限长归验证方、规范用语用 SHOULD"的在议立场一致。
- **nonce 防重放**:UCAN spec §Nonce(REQUIRED)。
- **序列化与签名**:RFC 8785(JCS)+ RFC 8032(Ed25519),与
  status.v1 / tlog.v1 全线一致。

### 9.2 学术依据(引用已核实)

1. **Sunil Prakash. "AIP: Agent Identity Protocol for Verifiable
   Delegation Across MCP and A2A." arXiv:2603.24775, 2026.**
   (作者单位 Indian School of Business;同名 IETF 草案
   draft-prakash-aip-00。)核实要点:
   - 论文摘要明确综述结论:"In our survey of eleven categories of prior
     work, we did not identify a prior implemented protocol that jointly
     combines public-key verifiable delegation, holder-side attenuation,
     expressive chained policy, transport bindings across MCP/A2A/HTTP,
     and provenance-oriented completion records."
   - JWT 不可衰减缺口的论证(§2 综述,针对 Agentic JWT 与 OAuth 侧
     profile 各出现一次):"JWTs are immutable after signing, so a
     delegatee cannot attenuate authority without minting a new token
     that breaks the cryptographic chain."
   - 其方案(IBCT:单跳 JWT + 多跳 Biscuit/Datalog)与本设计的关系:
     同一缺口的两种回应。AIP 以 Biscuit 追加块实现离线可验的收窄;
     本设计以显式凭证链 + 在线新鲜度实现同一收窄不变式,吊销传播
     有 60 秒上界(§8.2 对照表)。两者的收窄不变式(narrow-only,
     verifier 每跳必查)一致。
   - **引用纪律(-02 依评审警示补写)**:评审人指出该论文存在多处
     错误、引用须非常谨慎。本设计对它的依赖仅限上列**逐字核实过的
     引文**,不采信其余论断,也不以其为任何设计决策的单独依据。
2. **A. Birgisson, J. G. Politz, Ú. Erlingsson, A. Taly, M. Vrable,
   M. Lentczner. "Macaroons: Cookies with Contextual Caveats for
   Decentralized Authorization in the Cloud." NDSS 2014.**
   holder-attenuation 与 caveat 概念的学术源头(HMAC 链;其"验证方
   即潜在伪造方"的缺陷是后续公钥方案的共同出发点,AIP 论文 §2 亦引)。
   **bearer 区别(-02 依评审意见写明)**:macaroons(及其公钥后继
   Biscuit)是 **bearer token**——持有即可行使、可静默转手;本设计
   每跳由 delegator 自持密钥签名、行权处又有叶绑定与出示方认证
   (§5.3/§6.2),主体绑定模型与 bearer 相反。本设计仅借用其
   **caveat 概念**,不采用其令牌机制,不存在机制层面的依赖或兼容
   问题。
3. 相关 IETF 草案(现状核实,非定稿标准,仅作生态坐标):
   draft-prakash-aip-00(AIP 协议规范化)、
   draft-singla-agent-identity-protocol-03(另一同名 AIP:JWT Principal
   Token 委托链,2026-06,与 arXiv 论文非同一作者体系)——
   两者的并存本身佐证:agent 委托层尚无收敛标准,正是公开征求意见的
   合理时机。

### 9.3 同域在研方案对比(2026-08 快照)

两个直接同行方案,均于 2026 年 5–8 月经 W3C CCG 列表公开征评,
均已逐项核实(核实日期 2026-08-12);对比结论:**层次互补而非竞争**。

#### 9.3.1 HDP(draft-helixar-hdp-agentic-delegation-01,Helixar)

Human Delegation Provenance Protocol:记录"哪个人授权了哪个 agent、
什么范围、经过怎样的转手链",仅凭签发方公钥即可离线验证,无中心
注册表(Informational 定位;datatracker 与 CCG 征评帖 2026Aug/0002,
实现与测试向量 github.com/Helixar-AI/HDP)。

| 维度 | HDP v0.1 | jiaozi.delegation.v1 |
|---|---|---|
| 凭证性质 | 取证物:"provenance and tamper evidence, not runtime enforcement … an evidence trail, not a capability boundary"(其 §10.1) | 授权物:运行时能力边界,验证方按叶授权放行/拒绝 |
| 每跳签名密钥 | **单一签发方密钥**签所有 root 与 hop 签名(其 -01 修订说明),换取"仅凭签发方公钥离线可验";其公开问题 #1 自认 per-agent hop keys 问责更强、但失去离线保证("Per-agent hop keys would give stronger per-hop accountability at the cost of that offline guarantee") | **每跳由 delegator 自持密钥独立签名**——问责精确到跳;代价是放弃离线验证,与本协议在线新鲜度模型一致(D-8 已声明) |
| 收窄语义 | scope 为自定义对象(其公开问题 #3 正征询是否改用 ODRL profile);定位是取证而非运行时执行,不设能力边界(其 §10.1) | 单调收窄 MUST 铁律,违反整链拒绝(§5.1);运行时按叶授权放行/拒绝 |
| 链尾截断 | 其 §10.4 自述删尾验证仍通过,建议带外完整性检查;链长承诺列为未来候选 | 叶绑定使截断不构成权限提升,无需链长承诺(§5.3) |
| 吊销 | 无 mid-chain revocation,靠过期与会话终止(其 §10.6) | status.v1 60 秒新鲜度联动,任一环吊销/锁定 ≤ 60 秒全链下游失效(§8) |
| 根锚定 | 签发方记录的人类 principal | 签发方核验并登记的 KYB 法人 attest.v1(§7.1) |

互补关系是 HDP 自己点出的:其 §10.6 建议需要级联吊销的部署"layer a
capability system that supports cascade revocation at the application
layer"——本设计恰好是那一层 capability 系统;反之,HDP 的取证链可
补足本设计不承诺的审计完整性(§5.3 残余面)。

#### 9.3.2 Vouch Protocol(W3C CG Report v1.6.2,2026-05-31)

Gaddam(Vouch Protocol)与 Manu Sporny(Digital Bazaar)共同署名的
CCG 社区组报告,自我定位是"a layer that sits beneath, and
complements, agent identity and delegation specifications"(其
Abstract);§9 定义了资源绑定的委托链,是目前同域分量最重的相关
工作(spec:github.com/vouch-protocol/vouch,docs/specs/
w3c-cg-report.md)。

其 §9 与本设计的对照:

| 维度 | Vouch §9 | jiaozi.delegation.v1 |
|---|---|---|
| 标准对齐 | 语义对齐 ZCAP-LD,JCS(RFC 8785)序列化,不用 JSON-LD 规范化 | 同为 ZCAP/UCAN 对齐 + JCS 系(§4.1 D-1)——序列化选型同路 |
| 收窄强度 | **SHOULD**:收窄走 §9.5 Inverse Capability Pattern("delegation links can only narrow, never broaden"),实现层 SHOULD 遵循 | **MUST 铁律**:四条不变式逐跳强制,违反整链拒绝;未知 caveat 类型/格式 fail-closed 整链拒绝(§4.3/§4.5 D-3) |
| 链节约束 | 每链节 MUST 绑定 `resource` URI(资源绑定);temporal bounds 必填 | 权限词汇表 = 根 attest.v1 行为边界;caveats 只增不减;`expiresAt` 必填且只短不长;资源指定在 invocation 层 MUST(§6.2),链上收窄经 `allowedResources`(§4.3)——-02 起补齐资源维度 |
| 深度上限 | MUST 限深,RECOMMENDED ≤ 5(其 §9.4) | SHOULD 限长(验证方启发式),一期 profile 默认 3(§3 T6) |
| 根锚定 | 根 issuer 为 "a trusted principal",由验证方策略认定(其 §9.3 step 4) | 根 MUST 锚定签发方 KYB 核验的法人 attest.v1,可追责性是协议性质(§7.1 D-7) |
| 吊销 | 心跳协议(Heartbeat)承担运行时状态连续性,委托链本身无吊销联动语义 | status.v1 60 秒新鲜度逐环联动(§8) |
| 测试向量 | 有(其 §1.2:双证明 PQ profile 附 Python/TypeScript/Go 参考实现与公开跨实现测试向量) | 一期实现工单交付项(§11.1) |

关系声明:Vouch 的"持续状态可验证"层与本设计的"多跳授权链"层
正交互补——其报告 Abstract 明言自身"位于身份与委托规范之下并与之
互补";本设计正面引用其 §9 为先行相关工作,欢迎跨规范互授粉
(两者同为 CCG 场内的 JCS 系方案,桥接成本低)。

### 9.4 评审补录的相关工作(-02 新增)

-02 评审意见给出一批同域相关工作,逐项核实后收录(核实日期
2026-08-27,另注者除外);此处只做一两句定位,不展开对比:

- **SPKI/SDSI(RFC 2693,1999)**——证书作 capability 的**首创**
  (授权直接绑定密钥,支持委托与收窄,不经全局命名),本设计
  "凭证链 + 逐跳收窄"路线的历史源头,列首位。
- **KYA-OS(DIF Trusted AI Agents WG)**——以 W3C VC 做 capability
  certificate 的多跳委托方案(根锚 "Responsible Party",StatusList2021
  吊销,MCP 绑定参考实现),与本设计互补性强的在研同行;反馈对接
  已在进行(核实 2026-08-12)。
- **French Toast JWT(FT-JWT)**——JWT 的链式委托与权限收窄
  (delegation and permission attenuation for JWTs),对"JWT 不可
  衰减"缺口的 JWT 系回应。
- **PIC(Provenance Identity Continuity,Nitro Agility,draft 0.1)**——
  以"因果链证明"替代"令牌持有"的授权连续性模型;三不变量(origin
  不变、链路可追、操作集只缩 `ops_i ⊆ ops_{i-1}`)与本设计单调收窄
  同族,并同样主张以结构手段消解混淆代理。
- **Cedarling(Janssen Project / Linux Foundation)**——嵌入式 Cedar
  策略决策点(浏览器/移动端/服务端可内嵌);Cedar 若进入 §4.5 的
  caveat 格式候选评估,此为现成的执行器生态。
- **IETF OAuth WG(官名 Web Authorization Protocol)**——Txn-Token、
  agent 授权等在研 I-D 的归口;评审清单所列名称与该 WG 官名一致,
  按此收录。
- **Transaction Tokens(draft-ietf-oauth-transaction-tokens,OAuth WG
  在研)**——信任域内沿调用链传播用户/工作负载身份与授权上下文的
  短命签名令牌,与本设计同样关注"链上每跳的上下文不被篡改",但属
  单信任域 JWT 系,非 holder-attenuable。
- **Replicable Capability System**——评审人提及;未能独立核实到对应
  公开规范,列名待考(依本仓引用纪律作降级措辞,不注核实日期)。

## 10. 零发明自查表

### 10.1 采用对照(结构 → 标准条款)

| 本设计章节 | 结构 | 标准条款 | 采用方式 |
|---|---|---|---|
| §2 / §5.1 | 收窄不变式(restate-or-attenuate) | UCAN spec §Attenuation | 语义逐字采用 |
| §4.2 `parentRef` | 父凭证引用 | ZCAP `parentCapability`;UCAN §Token Resolution(CID 内容寻址) | ID 引用改为内容哈希引用,寻址精神同 UCAN;定位提示拆为可选 `parentLocation` |
| §4.2 `delegator`/`delegatee` | 每跳收发主体 | UCAN Delegation `iss`/`aud` | 字段语义一一对应 |
| §4.2 `rootCertId` | 链主体锚 | UCAN Delegation `sub`(Subject) | 采用;禁 `sub: null`(D-5) |
| §4.2 `nonce` | 防重放 | UCAN spec §Nonce | 全文采用 |
| §4.2 `expiresAt` | 时间收窄 | UCAN §Time Bounds;ZCAP `expires` 不得宽于父级 | 采用并收严(必填、禁 null) |
| §4.2 `caveats` | 约束继承只增 | ZCAP §Caveats;macaroons(NDSS 2014) | 语义逐字采用;deny-only 不变量显式化(§4.3) |
| §4.3 `allowedResources` | 链上资源收窄 | ZCAP §Caveats(约束语义);Vouch §9 资源绑定同精神 | caveat 类型化采用,交集语义(§5.1 (4)) |
| §5.2 第 1 步 | 主体对齐 | UCAN Delegation §Principal Alignment | 逐字采用(aud→iss 链回 Subject) |
| §5.2 第 1 步 | 逐跳验签 | UCAN Delegation §Signature Validation;ZCAP delegation proof | 逐字采用 |
| §5.2 第 0 步 | 链长上限 | ZCAP §Delegated Capability(SHOULD ≤ 10) | 语义采用:验证方 SHOULD 设上限(启发式);一期 profile 默认 3(-02 由协议硬上限改回 SHOULD 策略) |
| §5.2 第 4 步 / §5.3 | 叶绑定(链 MUST 终止于出示方) | UCAN Invocation §Proof Chains("ending at the invoker (`iss`)");ZCAP §Invocation(`capabilityInvocation` proof 由叶凭证 controller 签署) | 语义采用;以既有单跳门认证的主体做等值比对实现,零新增机制(D-9) |
| §6.2 invocation `resource` | 资源指定(designation) | ZCAP `invocationTarget`(root zcap MUST 具 URI 目标);UCAN Invocation(invocation 指定作用对象);Vouch §9 链节资源绑定 | 语义采用;收严为缺失即拒(fail-closed) |
| §6.3 | 资源标识规范化 | RFC 3986 §6.2.2 / §6.2.3 | 逐字采用 |
| §6.5 | 资源参数须随委托授予 | object-capability 文献通例(Hardy 1988 的对策面) | 语义采用 |
| §5.1 推论 | 每跳收窄 verifier 必查 | draft-prakash-aip-00 §3.3 | 语义采用 |
| §7.2 | 整链随请求出示 | ZCAP §Delegated Capability(链全量提交,验证方免解引用) | 逐字采用 |
| §4.1 | 签名壳 / canonical JSON | RFC 8032 / RFC 8785;`jiaozi.status.v1` 既有壳 | 全文采用 |
| §4.4 / §7.1 | 权限词汇表 = 行为边界 | `jiaozi.attest.v1` `behaviorBoundary`(本协议既有) | 复用,零改动 |
| §8 | 活性 = 新鲜状态凭证 | `jiaozi.status.v1`(本协议既有,60 秒 TTL) | 复用,零改动 |

### 10.2 偏离声明(全部偏离均为载体/裁剪/收严层面,无新密码学结构)

| # | 偏离 | 理由 | 风险评估 |
|---|---|---|---|
| D-1 | 序列化用 canonical JSON(RFC 8785)+ Ed25519 壳,不用 UCAN 的 DAG-CBOR/IPLD envelope,也不用 ZCAP 的 JSON-LD + Data Integrity proof | 协议全线(status.v1 / tlog.v1)同一签名壳,依赖方复用验签代码;不引入 IPLD/JSON-LD 依赖 | 无密码学影响:被签名的语义字段与两标准一一对应,仅编码不同;与 tlog D-1 同类,跨生态互操作留二期桥接 |
| D-2 | 权限为扁平字符串 + 精确匹配集合包含;无 UCAN Command 的路径层级(`/crypto` 证明 `/crypto/sign`)、无 UCAN Policy Language、无 ZCAP 的 URL 前缀收窄、无通配符 | 一期词汇表来自 behaviorBoundary 的自由字符串,尚无层级结构;精确匹配的包含判定最简且无歧义 | 表达力收窄属安全方向(拒绝面更大);后续若引入层级,按 UCAN §Command Segment Structure 语义扩展并出 v2 |
| D-3 | 未知 caveat 类型/未知 caveatFormat 整链拒绝(fail-closed);UCAN 允许忽略与本次调用无关的不理解条件 | 一期 caveat 注册表极小(§4.3),fail-closed 与 requireTrust 现行"unknown 状态按不可信处理"的基调一致 | 互操作面变小(合法但带新型 caveat 的链会被拒),以注册表修订流程与格式 profile 准入流程(§4.5)弥补 |
| D-4 | `expiresAt` 必填且禁 `null`(UCAN 允许 `exp: null` 永不过期) | 无限期委托与"授权只缩不放、可追责"的产品语义冲突;ZCAP 亦建议短有效期 | 收严无风险 |
| D-5 | 禁 UCAN 的 `sub: null`("Powerline"全权转授模式) | 该模式绕过"链锚定到单一根授权"的可追责设计目标;UCAN 自身也标注 "Use with care" | 收严无风险。同时承认(-02 依评审提醒):UCAN 一方对 Powerline 的适用场景有像样论证,本设计禁用只因与"链锚定单一根授权、追责到法人"的产品目标不符,非否定其一般价值 |
| D-6 | 禁多链授权合并(UCAN 的 authority union:"Merging capability authorities MUST follow set semantics … always additive") | 合并语义会让有效授权大于任何单链叶凭证,与"依赖方只看一条链的叶"心智冲突,易审计出错 | 收严;需要更大权限时应重新走一条委托链 |
| D-7 | 根授权锚定在签发方核验过的 attest.v1(机构核验的法人/主体),而非 ZCAP 自持 root zcap / UCAN 自证 Subject | 产品目标是"链能追责到已 KYB 法人";自证根无法承载此性质。根锚定语义 = 问责而非资源所有权(§7.1) | 引入对签发方登记的依赖——与本协议既有信任模型一致(签发方本就是 status.v1 的信任根),未新增信任方;agent 自建资源场景明示 out of scope(§7.1) |
| D-8 | 吊销复用 status.v1 在线新鲜度,不实现 UCAN Revocation 令牌 / ZCAP 吊销存储;代价是不支持离线验证 | §8.2 逐维对照:零新增机制、验证方无状态、传播上界 60 秒 | 诚实声明:分区/离线场景本协议整体不适用(单跳今天已如此);该取舍是模型级选择而非遗漏 |
| D-9(-02 新增) | invocation 不新增独立签名壳:ZCAP 要求 invocation 携带叶 controller 签署的 `capabilityInvocation` proof,本设计以"既有单跳门认证的 presenter == 叶 delegatee"等值检查承载同一义务(§6.2) | 复用既有认证通道,零新增机制;与 §5.3 叶绑定同构 | 安全性依赖单跳门的出示方认证强度(协议既有信任模型,非本设计新增假设);跨生态互操作若对端要求逐 invocation 签名,属 v2 桥接工作(§11.2) |

## 11. 分阶段实施

### 11.1 一期:单节点、Postgres 一张表(设计参考,非实现;链长 profile 默认 3)

一期不新增签发方权力:委托凭证由 delegator 本地签署(自持密钥),
**不经签发方**;签发方可选提供一张登记表用于审计与按凭证号检索
(登记与否不影响验证——链是自含的,验证只需 §7.2 出示物;登记表 URL
可作为 `parentLocation` 检索提示的取值来源,§4.2)。

```sql
-- 参考 schema(设计文档用途,非交付物)
CREATE TABLE delegations (
  delegation_hash  TEXT PRIMARY KEY,        -- "sha256:…",对 payload canonical JSON
  root_cert_id     TEXT NOT NULL,           -- 链根凭证号(检索键)
  parent_ref       TEXT NOT NULL,           -- §4.2 parentRef
  delegator        TEXT NOT NULL,
  delegatee        TEXT NOT NULL,
  credential_json  JSONB NOT NULL,          -- §4.1 三元组原文
  expires_at       TIMESTAMPTZ NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX delegations_root_idx ON delegations (root_cert_id);
CREATE INDEX delegations_delegatee_idx ON delegations (delegatee);
```

一期交付边界(实现工单在公开意见期后另立):

- gdid-core:`jiaozi.delegation.v1` 的构造/校验纯函数与 §5.2 验证算法
  (含拒绝码表与 §6 invocation 判定)+ 测试向量(合法链、每类违例各
  至少一例,含 `resource_missing` 与 `allowedResources` 交集用例);
- SDK:§7.3 的 `delegation` 选项(默认关闭,单跳行为零变化);
- API(可选):`POST /api/delegations`(登记,验签后入表)与
  `GET /api/delegations?rootCertId=`(审计检索);登记事件哈希可作为
  tlog 的 detail record 进透明日志(与 tlog 设计正交,不新增日志事件
  类型,留 tlog v2 修订流程决定);
- 示例:三跳链 demo(老板 → 采购 → 支付),演示越权放大被拒、
  中间环吊销 60 秒内下游失效、未指定资源被拒(fail-closed)。

### 11.2 二期与扩展(意见期后按需另立)

- 权限层级语义(对齐 UCAN §Command Segment Structure)与 caveat 格式
  profile 评估:**Cedar 为候选**(形式化子集证明能力,评审人推荐;
  准入条件 = 可证明追加 caveat 不扩权,§4.5),无承诺;
- 跨签发方链(delegator/delegatee 持不同签发方凭证)的信任根协商。
  评审立场记档(-02):能力模型下"永远不需要跨签发方联邦"——
  **递归问责**(每跳问责到其直接 delegator)是联邦的替代路线;二期
  评估时两条路线并陈,不预设结论;
- 与 UCAN/ZCAP 的双向桥接(载体转换器,消除 D-1 的互操作缺口);
  payload 一等 `resource` 字段与 ZCAP `invocationTarget` 的对齐、
  designation 凭证化(§6.6)在此一并评估(BR-11 留桥);
- **裸公钥链尾 delegatee(已识别扩展,-02 预告;评审建议)**:允许
  链尾受托方以裸公钥(无 JIAOZI 凭证)受托,回应"新建 agent/临时
  程序即时受托"的真实生命周期需求。v1 不实现(全员持证,保 G3 逐环
  活性语义完整);二期若开,边界四条预告如下,届时 MUST NOT 放松:
  1. 裸钥主体只允许出现在**链尾**,MUST NOT 再转授;
  2. 其**直接 delegator MUST 是持证可追责实体**——问责递归归于
     delegator,"面具背后是实名人"焊死;
  3. 撤销语义 = 撤销**上游那条委托边**(由该 delegator 吊销该条
     delegation),而非撤销裸钥主体本身(主体无凭证可吊;吊主体会
     误伤该 delegator 的其他委托);
  4. 此类委托 SHOULD 用**极短 `expiresAt`**,以自然过期为主、主动
     撤销为辅(与 status.v1 短命哲学同构);
- 委托事件进透明日志的正式化(tlog 修订流程);
- 选择性披露(链上主体身份的最小披露)与收件箱既有 SD-JWT/BBS+ 评估
  工单合流。

## 12. 参考文献

- **UCAN v1.0** — User Controlled Authorization Network Specification.
  <https://github.com/ucan-wg/spec>(§Attenuation、§Nonce、§Time、
  §Command、§Token Resolution;子规范 Delegation/Invocation 为
  REQUIRED,Revocation 为 RECOMMENDED)
- **UCAN Delegation, Version 1.0.0** —
  <https://github.com/ucan-wg/delegation>(payload 字段表、
  §Token Validation、§Principal Alignment、§Signature Validation)
- **UCAN Invocation** — <https://github.com/ucan-wg/invocation>
  (§Proof Chains:证明链 MUST 终止于 invoker;§5.3 叶绑定所引,
  核实 2026-08-12)
- **UCAN Revocation** — <https://github.com/ucan-wg/revocation>
  (§8.2 对照所引的吊销模型)
- **W3C CCG, Authorization Capabilities (ZCAP) v0.4.0-draft** —
  <https://w3c-ccg.github.io/zcap-spec/>(W3C CCG 工作项草案,非 W3C
  标准;§Root Capability(含 `invocationTarget`)、§Delegated
  Capability、§Caveats、§Invocation——后两者为 §5.3 叶绑定与 §6 资源
  指定所引,核实 2026-08-12)
- **N. Hardy.** *The Confused Deputy (or why capabilities might have
  been invented).* ACM SIGOPS Operating Systems Review 22(4), 1988.
  (§3 T4 / §6.5 混淆代理定性所引)
- **RFC 2693** — SPKI Certificate Theory. C. Ellison, B. Frantz,
  B. Lampson, R. Rivest, B. Thomas, T. Ylonen, 1999.
  <https://www.rfc-editor.org/rfc/rfc2693>(证书作 capability 的首创,
  §9.4;核实 2026-08-27)
- **Sunil Prakash.** *AIP: Agent Identity Protocol for Verifiable
  Delegation Across MCP and A2A.* arXiv:2603.24775, 2026.
  <https://arxiv.org/abs/2603.24775>(引用纪律见 §9.2 第 1 条)
- **draft-prakash-aip-00** — Agent Identity Protocol (AIP): Verifiable
  Delegation for AI Agent Systems(§3.3 Scope Attenuation).
  <https://www.ietf.org/archive/id/draft-prakash-aip-00.html>
- **draft-singla-agent-identity-protocol-03** — Agent Identity Protocol
  (AIP): Decentralized Identity and Delegation for AI Agents, 2026-06.
  <https://datatracker.ietf.org/doc/draft-singla-agent-identity-protocol/03/>
- **draft-helixar-hdp-agentic-delegation-01** — Human Delegation
  Provenance (HDP) for Agentic Delegation. S. Dalugoda (Helixar), 2026-08.
  <https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/>
  (§10.1、§10.4、§10.6;实现与测试向量
  <https://github.com/Helixar-AI/HDP>;核实 2026-08-12)
- **HDP CCG 征评帖** — "draft-helixar-hdp-agentic-delegation-01:
  chain-of-custody for agentic delegation (revision, seeking review)",
  public-credentials 列表,2026-08-03(公开问题 #1/#2/#4 出处).
  <https://lists.w3.org/Archives/Public/public-credentials/2026Aug/0002.html>
  (核实 2026-08-12)
- **Vouch Protocol** — Continuous State Verifiability for Autonomous AI
  Agents, W3C Community Group Report v1.6.2, 2026-05-31.
  R. Gaddam (Vouch Protocol), M. Sporny (Digital Bazaar).
  <https://github.com/vouch-protocol/vouch/blob/main/docs/specs/w3c-cg-report.md>
  (§9 Delegation Chains;核实 2026-08-12)
- **CCG zCap 工作项重启帖** — "Restarting work on the zCap
  (Authorization Capabilities) work item", D. Zagidulin, 2026-04-02.
  <https://lists.w3.org/Archives/Public/public-credentials/2026Apr/0029.html>
  (v0.4 对齐生产部署、v0.5 征集新用例;DIF Delegated Authorization
  Task Force 评估结论出处;核实 2026-08-12)
- **KYA-OS** — Know Your Agent Operating System, DIF Trusted AI Agents
  WG(KYA-OS Task Force).<https://github.com/decentralized-identity/kya-os-mcp>
  与 <https://www.kya-os.org>(VC 作 capability certificate 的多跳委托;
  核实 2026-08-12)
- **French Toast JWT (FT-JWT)** — Delegation and Permission Attenuation
  for JWTs. <https://github.com/ciamshrek/french-toast-jwt>
  (核实 2026-08-27)
- **PIC** — Provenance Identity Continuity (PIC) Model Specification,
  draft 0.1(steward: Nitro Agility;model: N. Gallo).
  <https://github.com/pic-protocol/pic-spec>(核实 2026-08-27)
- **Cedarling** — Janssen Project(Linux Foundation)embeddable Cedar
  policy decision point. <https://docs.jans.io/stable/cedarling/>
  (核实 2026-08-27)
- **Transaction Tokens** — draft-ietf-oauth-transaction-tokens,
  IETF OAuth WG(Web Authorization Protocol)在研 I-D.
  <https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/>
  (核实 2026-08-27)
- **A. Birgisson et al.** *Macaroons: Cookies with Contextual Caveats
  for Decentralized Authorization in the Cloud.* NDSS 2014.
- **RFC 8785** — JSON Canonicalization Scheme (JCS).
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA).
- **RFC 3986** — Uniform Resource Identifier (URI): Generic Syntax
  (§6.2.2/§6.2.3 规范化,§6.3 所引).
- **RFC 3339** — Date and Time on the Internet: Timestamps.
- **RFC 2119 / RFC 8174** — Key words for use in RFCs.
- `jiaozi.status.v1` — `standards/status-v1/SPEC.md`(签名壳、TTL、
  serial 语义;§8.1 自包含说明的规范正文)
- `jiaozi.tlog.v1` — `standards/tlog-v1/DESIGN.md`(本系列设计文档的
  结构与自查表范式)
- `docs/interop-gaps.md` — G6(本设计回应的缝隙立案)

---

## 附录 A. 公开征求意见投递计划(v1.0-design.2 修订)

> v1.0-design.1 附录原为冷启动新帖文案;v1.0-design.2 起改为
> **回帖接线**策略(见修订记录),本附录改为投递计划,各通道终稿
> 文案统一放 `docs/outbox/`,由用户过目后亲自发出。

### A.1 主通道:CCG 回帖(接 HDP 征评 thread)

- **不发新帖**,回帖接入 2026-08-03 的 HDP 征评讨论串
  (<https://lists.w3.org/Archives/Public/public-credentials/2026Aug/0002.html>,
  评审人含 Alan Karp、Bob Wyman、Sankarshan Mukhopadhyay)。理由:
  同域直接同行正在征评,回帖自带上下文与评审人;CCG 社区正严打
  AI 生成灌水(Slopification 讨论),冷启动长帖易被当噪音,短而实、
  带证据链接的回帖是当前唯一得体的进场方式。
- 主题行沿用原帖加 `Re:` 前缀:
  `Re: draft-helixar-hdp-agentic-delegation-01: chain-of-custody for
  agentic delegation (revision, seeking review)`。
- 回帖结构:先实质评论 HDP 的公开问题 #1(单钥 vs 每跳密钥)与
  #2(链尾截断,给出 §5.3 的能力模型答案),再一段介绍本互补设计
  并给文档链接、邀请评审;全文 ≤ 300 词。
- **终稿:`docs/outbox/ccg-delegation-reply.md`**(本人署名手工发送,
  发送人 hello@jiaozi.io)。
- -02 起新增的 §6(Invocation)为新设计面,依 L2 闸门随修订回同一
  线程公开征求意见,重点征集 invocation 章意见。

### A.2 存档通道:IETF Internet-Draft(个人提交)

- 与 CCG 回帖同步,将本设计整理为 Internet-Draft 提交 datatracker
  (个人提交,免费,永久署名档案)——邮件与私下沟通不算成果落档,
  一切贡献必须落在有公开时间戳与署名的档案里。
- 命名:`draft-li-jiaozi-delegation-00`;Informational 定位
  (与 HDP 同类,声明是设计征评、无实现)。
- **草稿与提交步骤:`docs/outbox/draft-li-jiaozi-delegation-00.md`**。

### A.3 进轨路径:zCap v0.5 用例输入 + DIF 对口

- CCG zCap 工作项重启中(Dmitri Zagidulin,2026-04-02,
  2026Apr/0029,核实 2026-08-12):先出 v0.4 对齐生产部署,随后
  **v0.5 征集新用例**。本设计的三项差异化——KYB 法人链根锚定、
  吊销与 status.v1 60 秒新鲜度联动、MUST 级收窄 + fail-closed
  未知 caveat——正是现成的 v0.5 用例输入;把差异化喂进 zCap v0.5
  比自立规范更快进入正式轨道。
- **一页用例素材:`docs/outbox/ccg-delegation-reply.md` 的
  "zCap v0.5 use-case input" 节**(zCap 征集开启时直接投)。
- DIF 对口 = **Trusted AI Agent WG 的 Delegated Authorization Task
  Force**(其评估结论"链式委托只有 zCap 与 UCAN 两家"正是本设计
  对齐的两个规范);CCG 回帖发出后把存档链接带到 DIF Slack 相关
  频道即可,不重发全文。

---

## 修订记录

- **v1.0-design.1(2026-08-10)**:首版落地,11 章 + 附录投递文案
  (冷启动新帖);零发明自查表 14 项采用 + D-1~D-8 偏离。
- **v1.0-design.2(2026-08-12)**:投稿前完善(BACKLOG 工单 #8
  "投稿前完善项" ①–⑦ 逐条对账):
  - **① HDP 对比**:新增 §8.3.1(单一签发方密钥 vs 每跳独立签名
    + 单调收窄的逐维对照表,引其公开问题 #1 自认单钥问责弱、
    §10.1/§10.6 原文);§11 补 HDP I-D、CCG 征评帖两条参考文献。
  - **② 链尾截断对策**:确认本设计结构上同样"每跳只向后承诺";
    新增 §5.3 分析与对策——**叶绑定**(链 MUST 精确终止于本次请求
    经单跳门认证的出示方),等价构造引 UCAN Invocation §Proof
    Chains 与 ZCAP §Invocation(capabilityInvocation);§5.2 伪码
    第 4 步集成 `presenter != leaf.delegatee → chain_leaf_mismatch`
    检查(输入表同步加 `presenter`),§6.3 拒绝码表与判定顺序、
    §3 威胁模型(新增 T7)、§9.1 采用对照表同步更新。结论:能力
    模型 + 单调收窄下截断不构成权限提升,无需引入签名链长承诺。
  - **③ "无对口 WG"佐证**:§1 动机新增 HDP 公开问题 #4 原文
    ("There is no obvious existing WG for agentic delegation
    provenance",2026Aug/0002)与 DIF Delegated Authorization TF
    "只有 zCap 与 UCAN 两家"结论(2026Apr/0029)作第三方佐证。
  - **④ CCG 回帖接线**:附录 A 由冷启动新帖改为回帖接 HDP 征评
    thread(A.1),终稿移至 `docs/outbox/ccg-delegation-reply.md`。
  - **⑤ IETF I-D 同步产出**:`docs/outbox/draft-li-jiaozi-delegation-00.md`
    (kramdown-rfc 风格 + datatracker 个人提交步骤),附录 A.2 接线。
  - **⑥ Vouch 对比**:新增 §8.3.2(CG Report v1.6.2 §9 逐维对照:
    收窄 SHOULD vs MUST 铁律、五跳 vs 三跳、trusted principal vs
    KYB 法人根锚、心跳 vs 60 秒新鲜度吊销联动),正面引用并声明
    层次互补;§11 补参考文献。
  - **⑦ zCap v0.5 用例路径**:附录 A.3 新增进轨路径说明,一页用例
    素材并入 `docs/outbox/ccg-delegation-reply.md`;DIF 对口明确为
    Trusted AI Agent WG 的 Delegated Authorization Task Force。
  - 杂项:缝隙台账引用路径修正为 `docs/interop-gaps.md`,G6 引文
    同步为收紧后措辞;外部引用全部标注核实日期(2026-08-12),
    未能核实项按降级措辞处理。
- **v1.0-design.3(2026-08-25)**:新增 §6.4——登记 attest.v1 可选顶层
  扩展容器 `delegation` 的结构预留(机账工单 #9,R3 签字 2026-08-25,
  裁决=可扩展容器方案):不透明对象、仅形状校验、随载荷整体进签名域、
  存量零变化;子字段仅文档层面登记(`delegator` 与 scope 收缩三维),
  运行时校验与链验证留二期实现工单。
  (注:该节随 -02 章节重排现为 §7.4。)
- **v1.0-design.4 = revision -02(2026-08-27)**:吸收两轮外部评审与
  一轮外部压力测试的修订。**致谢(acknowledgements)**:感谢
  **Alan Karp** 的两轮逐条评审(2026-08-18 三十条评论;2026-08-27
  第二轮五处补充意见)——本修订的主要结构变化(invocation 章、术语
  更正、链长 SHOULD 化、相关工作补录等)直接源于其意见;感谢一位
  外部评审者(an external reviewer)对资源模型与裸钥扩展边界的五条
  压力测试意见。attest.v1 / status.v1 语义零变更;§6 为新增设计面,
  回 CCG 线程公开征求意见。逐项修订:
  - **① 新增 §6 Invocation 章**(评审:invocation 缺失是 huge
    omission;裁决 BR-11 = C+A 组合):delegation / capability /
    invocation 三分(§6.1);invocation 对象与资源指定 **MUST**、
    缺失即拒 fail-closed(§6.2——资源收窄可选,资源指定不可选);
    资源标识 canonical form 规则(RFC 3986 §6.2.2/§6.2.3,§6.3);
    混淆代理(T4)重定性移入 invocation 层 + "作为参数传递的资源
    MUST 以委托形式授予被调用方"规则(§6.5);designation 与 caveats
    分离、designation 凭证化前瞻注记与一等 `resource` 字段留 v2 评估
    的注明(§6.6);§3 T4 同步改述;新增拒绝码 `resource_missing`。
    原 §6–§11 顺延为 §7–§12(旧修订记录中的节号指当时版本)。
  - **② delegation 层资源收窄**:§4.3 新增 `allowedResources` caveat
    类型(交集语义);§5.1 新增铁律第 (4) 条——资源维度单调收窄由
    实现推论升格为显式协议承诺。
  - **③ caveat 安全不变量与 caveatFormat 可插拔**:§4.3 显式写死内置
    词汇表 deny-only 不变量(单条只能否决不能授予);新增 §4.5
    `caveatFormat` 字段——内置键值格式为默认,Cedar 列候选 profile
    (评估中、无承诺),profile 准入条件 = **可证明追加 caveat 不
    扩权**(评审警告:复杂策略下追加约束可能在别的维度扩权);未知
    格式/混合格式 fail-closed(新拒绝码 `unknown_caveat_format`)。
  - **④ 链长改验证方启发式**:T6 与 §9.1 由"协议级硬上限 MUST ≤ 3"
    改为"验证方 SHOULD 设上限(启发式)",3 保留为一期实现 profile
    默认值;跨企业委托常见 ~10 跳的评审经验入 rationale。
  - **⑤ 吊销与新鲜度(§8.1 改写)**:显式吊销 + TTL 为传播上界的
    定性澄清;status.v1 签什么/怎么验的自包含说明;新鲜度策略旋钮
    (验证方 MAY 按操作价值收紧,直至直查 status 端点);可用性兜底
    段(双锚镜像 = 可用性锚、非第二信任根;签发方全灭 = fail-closed
    拒绝)。TTL 机制本体与凭证号体系零变更。
  - **⑥ 术语更正**:Delegator 由"让渡"改"分享"(委托是共享,
    delegator 不失去权限);"capability" 让位给能力安全含义,权限
    动词一律 permissions/actions;字段 `grantedCapabilities` 更名
    **`grantedPermissions`**(设计期无实现,零迁移成本;§7.4 attest
    容器登记的子字段名同步更名——该容器运行时不校验内部结构,零行为
    影响);§2 术语表新增 Capability(能力安全义)/ Resource /
    Invocation 条目。
  - **⑦ 澄清类文档改写**:`rootCertId` 保留理由补写(§4.2);D-5
    补注承认 Powerline 有其适用场景;新增可选 `parentLocation` 检索
    提示字段(§4.2,验证 MUST NOT 依赖);§5.1 grow-only 取舍显式
    声明(以表达力换判定平凡性,不做 caveat 语义子集比较);§5.3
    截断分析精简(HDP 上下文压缩为一段,结论不变);§7.1 根锚定 =
    问责而非资源所有权、agent 自建资源场景明示 out of scope;§11.2
    注明递归问责为跨签发方联邦的替代路线。
  - **⑧ 裸公钥链尾扩展预告**(裁决 BR-12 = v1 全员持证):§11.2 列为
    二期已识别扩展,边界四条写足——限链尾不得转授;直接 delegator
    持证可追责(MUST);撤销语义 = 撤销上游那条委托边(非主体);
    极短 TTL 自然过期优先。
  - **⑨ 参考文献与引用纪律**:新增 §9.4 相关工作补录(SPKI/SDSI
    居首、KYA-OS、French Toast JWT、PIC、Cedarling、IETF OAuth WG
    (Web Authorization Protocol)、Transaction Tokens;Replicable
    Capability System 未能独立核实、列名待考);§9.2 Prakash 2026
    加引用纪律声明(依赖仅限逐字核实引文);Macaroons/Biscuits 处
    写明 bearer token 与本设计主体绑定模型的区别;§12 参考文献同步
    补录(含 Hardy 1988、RFC 2693、RFC 3986)。
  - **⑩ 自查表与接口草案更新**:§10.1 采用对照新增资源指定/规范化/
    `allowedResources`/资源参数规则四行;新增偏离 D-9(invocation
    复用单跳门认证,不新增独立签名壳);§7.3 接口草案新增
    `delegation.resource` 配置与两个拒绝码。
