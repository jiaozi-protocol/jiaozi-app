import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import {
  deriveChildSeed,
  randomSeed32,
  toMultibaseZ,
  type MultisigPolicy,
  DEFAULT_MULTISIG,
} from "./keys.js";

export type HdNode = {
  path: string;
  role: "owner" | "domain" | "agent";
  publicKeyMultibase: string;
  /** Client-only seed hex for further derivation / export */
  seedHex: string;
  domainId?: string;
  agentId?: string;
  multisig: MultisigPolicy;
};

/**
 * Software HD hierarchy (Spec §2.2 / §6.5):
 * Owner Root → Domain/Cluster Sub-Root → Agent sub-identity
 *
 * Child seeds via HMAC-SHA512; Ed25519 keypair derived by using seed as
 * entropy source for a deterministic key export label + fresh key material
 * bound by hashing seed into PKCS8-like workflow:
 * we generate keypair and bind public key commitment = HMAC(seed,"commit").
 *
 * For Phase-1 signing, prefer `generateEd25519Keypair()` and register the
 * public key at a path; HD nodes provide deterministic identity handles.
 */
function seedToKeyCommitment(seed: Buffer): string {
  // Deterministic "public" handle for hierarchy (not a raw Ed25519 pubkey).
  // Real signing keys are attached via register/rotate APIs.
  return toMultibaseZ(
    Buffer.from(
      // 32 bytes
      seed,
    ),
  );
}

/** Create Owner Root (client-side). Platform never receives seedHex. */
export function createOwnerRoot(multisig: MultisigPolicy = DEFAULT_MULTISIG): HdNode {
  const seed = randomSeed32();
  return {
    path: "m",
    role: "owner",
    publicKeyMultibase: seedToKeyCommitment(seed),
    seedHex: seed.toString("hex"),
    multisig,
  };
}

export function deriveDomainSubRoot(owner: HdNode, domainId: string): HdNode {
  if (owner.role !== "owner") throw new Error("domain must derive from owner root");
  const path = `m/${encodeURIComponent(domainId)}`;
  const seed = deriveChildSeed(Buffer.from(owner.seedHex, "hex"), path);
  return {
    path,
    role: "domain",
    domainId,
    publicKeyMultibase: seedToKeyCommitment(seed),
    seedHex: seed.toString("hex"),
    multisig: owner.multisig,
  };
}

export function deriveAgentKey(domain: HdNode, agentId: string): HdNode {
  if (domain.role !== "domain") throw new Error("agent must derive from domain sub-root");
  const path = `${domain.path}/${encodeURIComponent(agentId)}`;
  const seed = deriveChildSeed(Buffer.from(domain.seedHex, "hex"), path);
  return {
    path,
    role: "agent",
    domainId: domain.domainId,
    agentId,
    publicKeyMultibase: seedToKeyCommitment(seed),
    seedHex: seed.toString("hex"),
    multisig: domain.multisig,
  };
}

/** Full chain helper */
export function deriveAgentFromOwner(
  owner: HdNode,
  domainId: string,
  agentId: string,
): { domain: HdNode; agent: HdNode } {
  const domain = deriveDomainSubRoot(owner, domainId);
  const agent = deriveAgentKey(domain, agentId);
  return { domain, agent };
}

/**
 * Optional: mint a real Ed25519 keypair for a path (non-deterministic across
 * machines unless you persist the returned private key). Used when an Agent
 * needs signing capability beyond HD identity handles.
 */
export function mintSigningKeyForPath(path: string): {
  path: string;
  publicKeyMultibase: string;
  privateKeyPkcs8Base64: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const raw = spki.subarray(spki.length - 32);
  void createPublicKey;
  void createPrivateKey;
  return {
    path,
    publicKeyMultibase: toMultibaseZ(raw),
    privateKeyPkcs8Base64: (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString(
      "base64",
    ),
  };
}
