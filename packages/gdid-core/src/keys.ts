import { createHash, createHmac, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";

/** Multisig policy — default 1-of-1; high-risk ops may require M-of-N. */
export type MultisigPolicy = {
  threshold: number;
  total: number;
  /** Optional list of owner pubkey multibase participants */
  participants?: string[];
};

export const DEFAULT_MULTISIG: MultisigPolicy = { threshold: 1, total: 1 };

export function assertMultisigPolicy(policy: MultisigPolicy): void {
  if (policy.threshold < 1 || policy.total < 1 || policy.threshold > policy.total) {
    throw new Error("invalid multisig policy");
  }
  if (policy.participants && policy.participants.length !== policy.total) {
    throw new Error("participants length must equal total");
  }
}

export type KeypairExport = {
  publicKeyMultibase: string;
  /** PKCS8 base64 — client-only; never send to platform */
  privateKeyPkcs8Base64: string;
  algorithm: "Ed25519";
};

function spkiToRawEd25519(spki: Buffer): Buffer {
  // SPKI for Ed25519 ends with 32-byte raw key
  return spki.subarray(spki.length - 32);
}

export function toMultibaseZ(raw32: Buffer): string {
  return `z${raw32.toString("base64url")}`;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

/**
 * 把公钥归一为 Ed25519VerificationKey2020 规范要求的标准 multibase：
 * multicodec 0xed01 前缀 + 32 字节原始公钥，base58btc 编码，即 z6Mk…。
 * 输入可以是院内格式（z + base64url 原始 32 字节，status.v1 §6 记录在案的历史分歧）
 * 或已是标准格式（原样返回）。无法解析时原样返回（宁可保留证据也不静默丢 key）。
 */
export function toStandardEd25519Multibase(multibase: string): string {
  if (/^z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(multibase)) return multibase;
  if (!multibase.startsWith("z")) return multibase;
  try {
    const raw = Buffer.from(multibase.slice(1), "base64url");
    if (raw.length !== 32) return multibase;
    const prefixed = new Uint8Array(34);
    prefixed[0] = 0xed;
    prefixed[1] = 0x01;
    prefixed.set(raw, 2);
    return "z" + base58btcEncode(prefixed);
  } catch {
    return multibase;
  }
}

export function generateEd25519Keypair(): KeypairExport {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  return {
    publicKeyMultibase: toMultibaseZ(spkiToRawEd25519(spki)),
    privateKeyPkcs8Base64: pkcs8.toString("base64"),
    algorithm: "Ed25519",
  };
}

export function signWithPkcs8(privateKeyPkcs8Base64: string, message: string): string {
  const key = {
    key: Buffer.from(privateKeyPkcs8Base64, "base64"),
    format: "der" as const,
    type: "pkcs8" as const,
  };
  return sign(null, Buffer.from(message, "utf8"), key).toString("base64url");
}

export function verifyWithMultibase(
  publicKeyMultibase: string,
  message: string,
  signatureBase64Url: string,
): boolean {
  try {
    const raw = Buffer.from(publicKeyMultibase.replace(/^z/, ""), "base64url");
    // Rebuild SPKI prefix for Ed25519
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const spki = Buffer.concat([spkiPrefix, raw]);
    const key = { key: spki, format: "der" as const, type: "spki" as const };
    return verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureBase64Url, "base64url"));
  } catch {
    return false;
  }
}

export type DidVerificationMethod = {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  revoked?: boolean;
};

/** Rotate: add new key as #key-N, retire previous authentication key. */
export function rotateDidDocumentKeys(input: {
  document: {
    id: string;
    controller: string;
    verificationMethod: DidVerificationMethod[];
    authentication: string[];
    assertionMethod: string[];
    [k: string]: unknown;
  };
  newPublicKeyMultibase: string;
}): typeof input.document {
  const did = input.document.id;
  const nextIndex = input.document.verificationMethod.length + 1;
  const newId = `${did}#key-${nextIndex}`;
  const methods = input.document.verificationMethod.map((vm) => {
    if (input.document.authentication.includes(vm.id)) {
      return { ...vm, revoked: true };
    }
    return vm;
  });
  methods.push({
    id: newId,
    type: "Ed25519VerificationKey2020",
    controller: input.document.controller,
    // 入档统一用规范编码,保持 DID 文档对外部解析器合规
    publicKeyMultibase: toStandardEd25519Multibase(input.newPublicKeyMultibase),
  });
  return {
    ...input.document,
    verificationMethod: methods,
    authentication: [newId],
    assertionMethod: [newId],
    updated: new Date().toISOString(),
    jiaoziOwnerBound: true,
  };
}

export function fingerprint(publicKeyMultibase: string): string {
  return createHash("sha256").update(publicKeyMultibase).digest("hex").slice(0, 16);
}

export function randomSeed32(): Buffer {
  return randomBytes(32);
}

export function deriveChildSeed(masterSeed: Buffer, path: string): Buffer {
  return createHmac("sha512", masterSeed).update(`jiaozi-hd:${path}`).digest().subarray(0, 32);
}
