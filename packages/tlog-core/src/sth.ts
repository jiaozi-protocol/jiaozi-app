/**
 * Tree head and Signed Tree Head (STH) — standards/tlog-v1/DESIGN.md §7.
 *
 * Field semantics follow RFC 9162 §4.9 / §4.10; the serialization deliberately
 * deviates (DESIGN.md §15.2 D-1): instead of the TLS presentation language the
 * STH uses the protocol-wide signature shell — Ed25519 over canonicalJson of
 * the payload, carried as { payload, signature, publicKeyMultibase } — which is
 * structurally identical to jiaozi.status.v1, so relying parties reuse the
 * same verification code path (this module reuses gdid-core key utilities).
 */

import { canonicalJson, signWithPkcs8, verifyWithMultibase } from "@jiaozi-protocol/gdid-core";
import { toPrefixedHash } from "./merkle.js";

export const STH_SCHEMA = "jiaozi.tlog-sth.v1" as const;

export interface SthPayloadV1 {
  schema: typeof STH_SCHEMA;
  /** Stable log identity = log base URL (DESIGN.md §7 / §8, RFC 9162 §4.4). */
  logId: string;
  treeSize: number;
  /** RFC 3339 UTC ms — the STH signing time (RFC 9162 §4.9 timestamp). */
  timestamp: string;
  /** "sha256:" + 64 hex — MTH of the first treeSize leaves. */
  rootHash: string;
}

export interface SignedTreeHeadV1 {
  payload: SthPayloadV1;
  /** base64url Ed25519 signature over canonicalJson(payload). */
  signature: string;
  publicKeyMultibase: string;
}

export function buildSthPayload(input: {
  logId: string;
  treeSize: number;
  /** Raw 32-byte root hash or already-prefixed "sha256:<hex>" string. */
  rootHash: Uint8Array | string;
  now?: Date;
}): SthPayloadV1 {
  if (!Number.isInteger(input.treeSize) || input.treeSize < 0) {
    throw new Error(`invalid treeSize: ${input.treeSize}`);
  }
  const rootHash =
    typeof input.rootHash === "string" ? input.rootHash : toPrefixedHash(input.rootHash);
  if (!/^sha256:[0-9a-f]{64}$/.test(rootHash)) {
    throw new Error(`invalid rootHash: ${rootHash}`);
  }
  return {
    schema: STH_SCHEMA,
    logId: input.logId,
    treeSize: input.treeSize,
    timestamp: (input.now ?? new Date()).toISOString(),
    rootHash,
  };
}

export function signTreeHead(
  payload: SthPayloadV1,
  privateKeyPkcs8Base64: string,
  publicKeyMultibase: string,
): SignedTreeHeadV1 {
  return {
    payload,
    signature: signWithPkcs8(privateKeyPkcs8Base64, canonicalJson(payload)),
    publicKeyMultibase,
  };
}

export function isSignedTreeHeadV1(value: unknown): value is SignedTreeHeadV1 {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.signature !== "string" || typeof v.publicKeyMultibase !== "string") return false;
  const p = v.payload as Record<string, unknown> | undefined;
  return Boolean(
    p &&
      typeof p === "object" &&
      p.schema === STH_SCHEMA &&
      typeof p.logId === "string" &&
      typeof p.treeSize === "number" &&
      Number.isInteger(p.treeSize) &&
      p.treeSize >= 0 &&
      typeof p.timestamp === "string" &&
      typeof p.rootHash === "string" &&
      /^sha256:[0-9a-f]{64}$/.test(p.rootHash),
  );
}

export type SthVerifyFailure =
  | "bad_shape"
  | "bad_signature"
  | "untrusted_key"
  | "log_id_mismatch"
  | "tree_size_regression";

export type SthVerifyResult =
  | { valid: true; payload: SthPayloadV1 }
  | { valid: false; reason: SthVerifyFailure };

/**
 * Relying-party verification per DESIGN.md §7: pin the log key (trustedKeys),
 * verify the signature, and reject treeSize regressions relative to the
 * largest already-seen tree (minTreeSize).
 */
export function verifySignedTreeHead(
  sth: unknown,
  opts?: {
    trustedKeys?: readonly string[];
    expectedLogId?: string;
    /** Largest treeSize already accepted; smaller STHs are rejected (§7 / T5). */
    minTreeSize?: number;
  },
): SthVerifyResult {
  if (!isSignedTreeHeadV1(sth)) return { valid: false, reason: "bad_shape" };
  const { payload, signature, publicKeyMultibase } = sth;
  if (opts?.trustedKeys && !opts.trustedKeys.includes(publicKeyMultibase)) {
    return { valid: false, reason: "untrusted_key" };
  }
  if (!verifyWithMultibase(publicKeyMultibase, canonicalJson(payload), signature)) {
    return { valid: false, reason: "bad_signature" };
  }
  if (opts?.expectedLogId && payload.logId !== opts.expectedLogId) {
    return { valid: false, reason: "log_id_mismatch" };
  }
  if (opts?.minTreeSize !== undefined && payload.treeSize < opts.minTreeSize) {
    return { valid: false, reason: "tree_size_regression" };
  }
  return { valid: true, payload };
}
