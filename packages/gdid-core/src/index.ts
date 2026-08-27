/** MVP attest summary — Spec §6.3 / docs/MVP_CONTRACT.md */

import {
  buildAgentDid,
  didWebHttpUrl,
  isCertId,
  normalizeDidInput,
  parseDidWeb,
} from "./did.js";

export {
  buildAgentDid,
  didWebHttpUrl,
  isCertId,
  normalizeDidInput,
  parseDidWeb,
};

export {
  DEFAULT_MULTISIG,
  assertMultisigPolicy,
  fingerprint,
  generateEd25519Keypair,
  rotateDidDocumentKeys,
  signWithPkcs8,
  toStandardEd25519Multibase,
  verifyWithMultibase,
  type KeypairExport,
  type MultisigPolicy,
} from "./keys.js";

import { toStandardEd25519Multibase } from "./keys.js";

export {
  createOwnerRoot,
  deriveAgentFromOwner,
  deriveAgentKey,
  deriveDomainSubRoot,
  mintSigningKeyForPath,
  type HdNode,
} from "./hd.js";

export {
  cloudAttestPlugin,
  runAttestationChain,
  softwarePlugin,
  teePlugin,
  tpmPlugin,
  type AttestationEvidence,
  type AttestationPlugin,
} from "./attest.js";

export {
  CREDIT_SCHEMA,
  asSha256Prefixed,
  buildMerkleProof,
  canonicalJson,
  chainLink,
  hashCreditEvent,
  hashLocalCreditDetail,
  isCreditEventV1,
  merkleRoot,
  sha256Hex,
  softwareAnchorReceipt,
  verifyMerkleProof,
  type CreditEventType,
  type CreditEventV1,
  type CreditSeverity,
  type MerkleProof,
} from "./credit.js";

export {
  STATUS_SCHEMA,
  buildStatusPayload,
  isStatusCredentialV1,
  signStatusPayload,
  verifyStatusCredential,
  type CertLiveStatus,
  type StatusCredentialV1,
  type StatusPayloadV1,
  type StatusVerifyFailure,
  type StatusVerifyResult,
} from "./status.js";

export const ATTEST_SCHEMA = "jiaozi.attest.v1" as const;

export type TrustLevel = "software" | "cloud_attest" | "tee" | "tpm" | "revoked";

export type CheckResult = "pass" | "fail" | "skip";

/**
 * 行为边界（GB/Z 185.3 注册核验材料之一）：权限 / 目标 / 约束。
 * 可选字段——主人自述的行为承诺，随认证摘要存证，吊销追责时对照。
 */
export interface BehaviorBoundaryV1 {
  permissions?: string[];
  goals?: string[];
  constraints?: string[];
}

export interface AttestSummaryV1 {
  schema: typeof ATTEST_SCHEMA;
  agentName: string;
  softwareGeneHash: string;
  /** 国密并行摘要（可选）：同一份基因材料的 SM3 哈希，"sm3:" + 64 hex（GB/T 32905-2016）。 */
  softwareGeneHashSm3?: string;
  checks: {
    maliciousApi: CheckResult;
    secretLeak: CheckResult;
  };
  score: number;
  trustLevel: TrustLevel;
  ownerPubkey: string;
  timestamp: string;
  clientNonce: string;
  behaviorBoundary?: BehaviorBoundaryV1;
  /**
   * 委托扩展容器（结构预留位，R3 签字 2026-08-25）。v1 验证器将其视为
   * **不透明对象**：出现时仅做"是对象"的形状校验，不校验内部结构、不参与
   * 签名域之外的任何逻辑判定；attest.v1 载荷整体签名时本字段自然进入签名域。
   * 初始已知子字段（仅文档层面登记，运行时不校验，语义对齐
   * standards/delegation-v1/DESIGN.md §4.2 / §6.3）：`delegator`（委托方
   * 标识：凭证号或 DID）与 scope 收缩相关字段（`grantedCapabilities` /
   * `caveats` / `expiresAt`，单调收窄铁律三维）。
   */
  delegation?: Record<string, unknown>;
}

export interface DidDocumentMinimal {
  /** DID Core JSON-LD 表示要求的 @context（2026-08 外部合规考试补齐） */
  "@context"?: string[];
  id: string;
  controller: string;
  /** 别名标识（W3C DID Core）。预留 GB/Z 185.2 OID 身份码：urn:oid:1.2.156.3088.… */
  alsoKnownAs?: string[];
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase?: string;
  }>;
  authentication: string[];
  assertionMethod: string[];
  jiaoziTrustLevel?: TrustLevel;
  jiaoziCertId?: string;
  created?: string;
  updated?: string;
}

export interface CertRecord {
  certId: string;
  did: string;
  trustLevel: TrustLevel;
  status: "active" | "suspended" | "revoked";
}

/**
 * Cert id: JIAOZI-YYYY-######（6 位起步补零，超出后位数自然增长，最多 9 位）。
 * 年容量 2 亿（2026-07-26 定案：Agent 增长太快，直接按两亿编排）；
 * 已发凭证标识永不改变，验证方按 (JIAOZI|JP|JJ)-\d{4}-\d{6,9} 解析。
 * 前缀沿革：JJ（2026-07-26 前）→ JP（2026-07-26）→ JIAOZI（2026-08-08，
 * 直接用协议正名，免缩写释义）。历史 JJ 输入经 normalizeCertId 归一到 JP
 * 查询；JP/JIAOZI 各自保持原标识（已签发凭证嵌入 DID 与签名工件，不改写）。
 */
export const CERT_SEQ_MAX = 200_000_000;

export const CERT_PREFIX = "JIAOZI" as const;

export function formatCertId(year: number, seq: number): string {
  if (seq < 1 || seq > CERT_SEQ_MAX) {
    throw new Error("cert sequence out of range");
  }
  return `${CERT_PREFIX}-${year}-${String(seq).padStart(6, "0")}`;
}

/**
 * GB/Z 185.2 身份码组装（结构已核实：官方发布会解读 + 逐条速查交叉验证，2026-07-28）：
 *   1.2.156.3088 . 版本 . 注册服务方 . 注册请求方 . 本体序列号 . 实例序列号
 * arcPrefix = 前缀+版本+注册服务方代码（由资质下发，配 JIAOZI_OID_ARC）；
 * 请求方/本体/实例三段由咱们分配。国标规则：核心功能变更→新本体序列号
 * （与去重键"密钥+代码摘要"同构，一张证书=一个本体版本）；实例级身份未建前恒为 1。
 */
export function composeOidIdentityCode(input: {
  arcPrefix: string;
  requesterCode: number | string;
  ontologySerial: number | string;
  instanceSerial?: number | string;
}): string {
  const seg = (v: number | string, name: string): string => {
    const s = String(v).trim();
    if (!/^[0-9A-Za-z]+$/.test(s)) throw new Error(`invalid oid segment ${name}: ${s}`);
    return s;
  };
  const arc = input.arcPrefix.trim().replace(/\.$/, "");
  if (!/^\d+(\.[0-9A-Za-z]+)+$/.test(arc)) {
    throw new Error(`invalid oid arc prefix: ${arc}`);
  }
  return [
    arc,
    seg(input.requesterCode, "requesterCode"),
    seg(input.ontologySerial, "ontologySerial"),
    seg(input.instanceSerial ?? 1, "instanceSerial"),
  ].join(".");
}

/**
 * 归一凭证标识:统一大写;历史 JJ 前缀映射到 JP(库内即以 JP 存储);
 * JP 与 JIAOZI 前缀各自保持原样(已签发标识永不改写)。非凭证标识仅 trim 原样返回。
 */
export function normalizeCertId(input: string): string {
  const trimmed = input.trim();
  const upper = trimmed.toUpperCase();
  if (!/^(JIAOZI|J[JP])-\d{4}-\d{6,9}$/.test(upper)) return trimmed;
  return upper.startsWith("JJ-") ? `JP${upper.slice(2)}` : upper;
}

export function isAttestSummaryV1(value: unknown): value is AttestSummaryV1 {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  const trust = v.trustLevel;
  const trustOk =
    trust === "software" ||
    trust === "cloud_attest" ||
    trust === "tee" ||
    trust === "tpm" ||
    trust === "revoked";
  // delegation 预留位:缺席合法;出现时仅做"是对象"形状校验(不透明,不看内部)
  const delegationOk =
    v.delegation === undefined ||
    (typeof v.delegation === "object" && v.delegation !== null && !Array.isArray(v.delegation));
  return (
    v.schema === ATTEST_SCHEMA &&
    delegationOk &&
    typeof v.agentName === "string" &&
    typeof v.softwareGeneHash === "string" &&
    typeof v.ownerPubkey === "string" &&
    typeof v.timestamp === "string" &&
    typeof v.clientNonce === "string" &&
    typeof v.score === "number" &&
    trustOk
  );
}

export const DID_DOCUMENT_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/ed25519-2020/v1",
];

export function createSoftwareDidDocument(input: {
  did: string;
  controller: string;
  certId: string;
  ownerPubkeyMultibase: string;
  /** GB/Z 185.2 OID 身份码（如 "1.2.156.3088.x.y"），有则写入 alsoKnownAs */
  oidIdentityCode?: string;
}): DidDocumentMinimal {
  const vmId = `${input.did}#key-1`;
  const now = new Date().toISOString();
  return {
    "@context": DID_DOCUMENT_CONTEXT,
    id: input.did,
    controller: input.controller,
    ...(input.oidIdentityCode ? { alsoKnownAs: [`urn:oid:${input.oidIdentityCode}`] } : {}),
    verificationMethod: [
      {
        id: vmId,
        type: "Ed25519VerificationKey2020",
        controller: input.controller,
        publicKeyMultibase: toStandardEd25519Multibase(input.ownerPubkeyMultibase),
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
    jiaoziTrustLevel: "software",
    jiaoziCertId: input.certId,
    created: now,
    updated: now,
  };
}

export function issueDidBundle(input: {
  coreHost: string;
  certId: string;
  ownerPubkeyMultibase: string;
  oidIdentityCode?: string;
}): { did: string; document: DidDocumentMinimal; httpUrl: string } {
  const did = buildAgentDid(input.coreHost, input.certId);
  const document = createSoftwareDidDocument({
    did,
    controller: did,
    certId: input.certId,
    ownerPubkeyMultibase: input.ownerPubkeyMultibase,
    oidIdentityCode: input.oidIdentityCode,
  });
  return { did, document, httpUrl: didWebHttpUrl(did) ?? "" };
}
