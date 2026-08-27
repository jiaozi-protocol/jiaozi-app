/** Credit event summaries + Merkle anchoring (Stage 3). Spec: local detail, central hash only. */

import { createHash } from "node:crypto";

export const CREDIT_SCHEMA = "jiaozi.credit.v1" as const;

export type CreditSeverity = "info" | "warn" | "critical";

export type CreditEventType =
  | "attest_issued"
  | "revoked"
  | "policy_pass"
  | "policy_fail"
  | "peer_verified"
  | "custom";

/** De-identified credit event — never include source code or PII. */
export interface CreditEventV1 {
  schema: typeof CREDIT_SCHEMA;
  /** DID or cert id of the subject Agent */
  subject: string;
  type: CreditEventType;
  /**
   * Hash of local detail blob (computed client-side).
   * Platform never receives the raw detail.
   */
  summaryHash: string;
  scoreDelta?: number;
  severity?: CreditSeverity;
  timestamp: string;
  clientNonce: string;
  /** Optional opaque labels (no PII) */
  tags?: string[];
}

export type MerkleProof = {
  leafHash: string;
  index: number;
  siblings: string[];
  root: string;
};

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Normalize to `sha256:<hex>` */
export function asSha256Prefixed(hexOrPrefixed: string): string {
  const t = hexOrPrefixed.trim();
  if (t.startsWith("sha256:")) return t.toLowerCase();
  if (/^[0-9a-f]{64}$/i.test(t)) return `sha256:${t.toLowerCase()}`;
  throw new Error("expected sha256 hex or sha256:<hex>");
}

export function isCreditEventV1(value: unknown): value is CreditEventV1 {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  const types: CreditEventType[] = [
    "attest_issued",
    "revoked",
    "policy_pass",
    "policy_fail",
    "peer_verified",
    "custom",
  ];
  const sevOk =
    v.severity === undefined ||
    v.severity === "info" ||
    v.severity === "warn" ||
    v.severity === "critical";
  return (
    v.schema === CREDIT_SCHEMA &&
    typeof v.subject === "string" &&
    typeof v.summaryHash === "string" &&
    typeof v.timestamp === "string" &&
    typeof v.clientNonce === "string" &&
    types.includes(v.type as CreditEventType) &&
    sevOk &&
    (v.scoreDelta === undefined || typeof v.scoreDelta === "number")
  );
}

/** Canonical JSON (sorted keys) for stable hashing. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((x) => canonicalJson(x)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/** Leaf hash for one credit event (prefixed sha256). */
export function hashCreditEvent(event: CreditEventV1): string {
  const normalized: CreditEventV1 = {
    schema: CREDIT_SCHEMA,
    subject: event.subject.trim(),
    type: event.type,
    summaryHash: asSha256Prefixed(event.summaryHash),
    timestamp: event.timestamp,
    clientNonce: event.clientNonce,
  };
  if (event.scoreDelta !== undefined) normalized.scoreDelta = event.scoreDelta;
  if (event.severity) normalized.severity = event.severity;
  if (event.tags?.length) normalized.tags = [...event.tags].sort();
  return `sha256:${sha256Hex(canonicalJson(normalized))}`;
}

function pairHash(left: string, right: string): string {
  const a = asSha256Prefixed(left).slice("sha256:".length);
  const b = asSha256Prefixed(right).slice("sha256:".length);
  return `sha256:${sha256Hex(Buffer.from(a + b, "utf8"))}`;
}

/** Build Merkle root from leaf hashes (duplicate last if odd). */
export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) {
    return `sha256:${sha256Hex("")}`;
  }
  let layer = leaves.map((l) => asSha256Prefixed(l));
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] ?? left;
      next.push(pairHash(left, right));
    }
    layer = next;
  }
  return layer[0];
}

export function buildMerkleProof(leaves: string[], index: number): MerkleProof {
  if (index < 0 || index >= leaves.length) {
    throw new Error("leaf index out of range");
  }
  const normalized = leaves.map((l) => asSha256Prefixed(l));
  const siblings: string[] = [];
  let layer = normalized;
  let idx = index;
  while (layer.length > 1) {
    const isRight = idx % 2 === 1;
    const pairIdx = isRight ? idx - 1 : idx + 1;
    const sibling = layer[pairIdx] ?? layer[idx];
    siblings.push(sibling);
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] ?? left;
      next.push(pairHash(left, right));
    }
    layer = next;
    idx = Math.floor(idx / 2);
  }
  return {
    leafHash: normalized[index],
    index,
    siblings,
    root: layer[0],
  };
}

export function verifyMerkleProof(proof: MerkleProof): boolean {
  let hash = asSha256Prefixed(proof.leafHash);
  let idx = proof.index;
  for (const sib of proof.siblings) {
    const sibling = asSha256Prefixed(sib);
    hash = idx % 2 === 1 ? pairHash(sibling, hash) : pairHash(hash, sibling);
    idx = Math.floor(idx / 2);
  }
  return hash === asSha256Prefixed(proof.root);
}

/** Hash-chain link: H(prevRoot || thisRoot) for sequential anchors. */
export function chainLink(prevRoot: string | null, thisRoot: string): string {
  const prev = prevRoot ? asSha256Prefixed(prevRoot) : `sha256:${"0".repeat(64)}`;
  const cur = asSha256Prefixed(thisRoot);
  return `sha256:${sha256Hex(prev + cur)}`;
}

/** Software anchor receipt (placeholder for real L1/timestamping). */
export function softwareAnchorReceipt(root: string, anchorId: string): {
  backend: "software";
  receipt: string;
  anchoredAt: string;
} {
  const r = asSha256Prefixed(root);
  return {
    backend: "software",
    receipt: `jiaozi:software-anchor:${anchorId}:${r}`,
    anchoredAt: new Date().toISOString(),
  };
}

/** Client helper: hash local detail without uploading it. */
export function hashLocalCreditDetail(detail: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(detail))}`;
}
