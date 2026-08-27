/**
 * Signed revocation-freshness status credential ("jiaozi.status.v1").
 * Design: docs/SECURITY_REVOCATION.md — layers 1 (signed short-TTL status)
 * and 2 (signature + monotonic serial against replay/cache poisoning).
 */

import { canonicalJson } from "./credit.js";
import { signWithPkcs8, verifyWithMultibase } from "./keys.js";
import type { TrustLevel } from "./index.js";

export const STATUS_SCHEMA = "jiaozi.status.v1" as const;

/**
 * suspended = 锁定（可逆，对齐 GB/Z 185.3 账户"锁定/解锁"生命周期）；
 * revoked = 吊销（不可逆）。验证方对 suspended 应按"暂不可信"处理。
 */
export type CertLiveStatus = "active" | "suspended" | "revoked" | "unknown";

export interface StatusPayloadV1 {
  schema: typeof STATUS_SCHEMA;
  certId: string;
  did: string | null;
  status: CertLiveStatus;
  trustLevel: TrustLevel | null;
  revocationReason?: string;
  /** Monotonic per issuer (epoch ms at signing). Verifiers MUST reject decreasing serials. */
  serial: number;
  signedAt: string;
  expiresAt: string;
  issuer: string;
}

export interface StatusCredentialV1 {
  payload: StatusPayloadV1;
  /** base64url Ed25519 signature over canonicalJson(payload) */
  signature: string;
  publicKeyMultibase: string;
}

export function buildStatusPayload(input: {
  certId: string;
  did: string | null;
  status: CertLiveStatus;
  trustLevel: TrustLevel | null;
  revocationReason?: string;
  issuer: string;
  ttlSeconds: number;
  now?: Date;
}): StatusPayloadV1 {
  const now = input.now ?? new Date();
  const payload: StatusPayloadV1 = {
    schema: STATUS_SCHEMA,
    certId: input.certId,
    did: input.did,
    status: input.status,
    trustLevel: input.trustLevel,
    serial: now.getTime(),
    signedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + input.ttlSeconds * 1000).toISOString(),
    issuer: input.issuer,
  };
  if (input.revocationReason) payload.revocationReason = input.revocationReason;
  return payload;
}

export function signStatusPayload(
  payload: StatusPayloadV1,
  privateKeyPkcs8Base64: string,
  publicKeyMultibase: string,
): StatusCredentialV1 {
  return {
    payload,
    signature: signWithPkcs8(privateKeyPkcs8Base64, canonicalJson(payload)),
    publicKeyMultibase,
  };
}

export type StatusVerifyFailure =
  | "bad_shape"
  | "bad_signature"
  | "expired"
  | "issuer_mismatch"
  | "untrusted_key"
  | "serial_regression";

export type StatusVerifyResult =
  | { valid: true; payload: StatusPayloadV1 }
  | { valid: false; reason: StatusVerifyFailure };

export function isStatusCredentialV1(value: unknown): value is StatusCredentialV1 {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.signature !== "string" || typeof v.publicKeyMultibase !== "string") return false;
  const p = v.payload as Record<string, unknown> | undefined;
  return Boolean(
    p &&
      p.schema === STATUS_SCHEMA &&
      typeof p.certId === "string" &&
      typeof p.serial === "number" &&
      typeof p.signedAt === "string" &&
      typeof p.expiresAt === "string" &&
      typeof p.issuer === "string" &&
      (p.status === "active" ||
        p.status === "suspended" ||
        p.status === "revoked" ||
        p.status === "unknown"),
  );
}

/**
 * Full verification for relying parties (fail-closed by default):
 * shape → signature → expiry → optional issuer pin → optional key pin →
 * optional monotonic serial floor (pass the last seen serial as minSerial).
 */
export function verifyStatusCredential(
  credential: unknown,
  opts?: {
    now?: Date;
    expectedIssuer?: string;
    trustedKeys?: readonly string[];
    minSerial?: number;
  },
): StatusVerifyResult {
  if (!isStatusCredentialV1(credential)) return { valid: false, reason: "bad_shape" };
  const { payload, signature, publicKeyMultibase } = credential;
  if (opts?.trustedKeys && !opts.trustedKeys.includes(publicKeyMultibase)) {
    return { valid: false, reason: "untrusted_key" };
  }
  if (!verifyWithMultibase(publicKeyMultibase, canonicalJson(payload), signature)) {
    return { valid: false, reason: "bad_signature" };
  }
  const now = opts?.now ?? new Date();
  if (now.getTime() > new Date(payload.expiresAt).getTime()) {
    return { valid: false, reason: "expired" };
  }
  if (opts?.expectedIssuer && payload.issuer !== opts.expectedIssuer) {
    return { valid: false, reason: "issuer_mismatch" };
  }
  if (opts?.minSerial !== undefined && payload.serial < opts.minSerial) {
    return { valid: false, reason: "serial_regression" };
  }
  return { valid: true, payload };
}
