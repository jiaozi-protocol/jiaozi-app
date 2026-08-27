/**
 * Merkle tree, inclusion proofs and consistency proofs — RFC 9162 §2.1,
 * adopted verbatim per standards/tlog-v1/DESIGN.md §5–§6 (zero-invention).
 *
 * HASH = SHA-256. Leaves and interior nodes are domain-separated with the
 * 0x00 / 0x01 prefixes; odd layers are NOT padded by duplicating the last
 * node (the tree shape is uniquely determined by the leaf count).
 *
 * All functions here operate on raw 32-byte hashes; the `sha256:<hex>` JSON
 * carrier used by the REST surface (§9) is handled by the helpers at the
 * bottom of this file.
 */

import { createHash } from "node:crypto";

export const LEAF_HASH_PREFIX = 0x00;
export const NODE_HASH_PREFIX = 0x01;

function sha256(...parts: readonly Uint8Array[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

/** MTH({}) = HASH() — hash of the empty string (RFC 9162 §2.1.1). */
export function emptyTreeRoot(): Buffer {
  return sha256();
}

/** Leaf hash: HASH(0x00 ‖ leafInput) (RFC 9162 §2.1.1). */
export function hashLeaf(leafInput: Uint8Array): Buffer {
  return sha256(Buffer.from([LEAF_HASH_PREFIX]), leafInput);
}

/** Interior node hash: HASH(0x01 ‖ left ‖ right) (RFC 9162 §2.1.1). */
export function hashChildren(left: Uint8Array, right: Uint8Array): Buffer {
  return sha256(Buffer.from([NODE_HASH_PREFIX]), left, right);
}

/** Largest power of two strictly smaller than n (n >= 2). */
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(n: number): boolean {
  if (n < 1) return false;
  while (n % 2 === 0) n /= 2;
  return n === 1;
}

/** MTH over the subtree covering leafHashes[lo, hi). */
function subtreeRoot(leafHashes: readonly Uint8Array[], lo: number, hi: number): Buffer {
  const n = hi - lo;
  if (n === 1) return Buffer.from(leafHashes[lo]);
  const k = largestPowerOfTwoBelow(n);
  return hashChildren(subtreeRoot(leafHashes, lo, lo + k), subtreeRoot(leafHashes, lo + k, hi));
}

/**
 * Merkle Tree Hash over already-hashed leaves (RFC 9162 §2.1.1 MTH, with the
 * leaf-hash step factored out so callers can keep leaf hashes materialized).
 */
export function merkleRootFromLeafHashes(leafHashes: readonly Uint8Array[]): Buffer {
  if (leafHashes.length === 0) return emptyTreeRoot();
  return subtreeRoot(leafHashes, 0, leafHashes.length);
}

function pathRec(m: number, leafHashes: readonly Uint8Array[], lo: number, hi: number): Buffer[] {
  const n = hi - lo;
  if (n === 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) return [...pathRec(m, leafHashes, lo, lo + k), subtreeRoot(leafHashes, lo + k, hi)];
  return [...pathRec(m - k, leafHashes, lo + k, hi), subtreeRoot(leafHashes, lo, lo + k)];
}

/** Inclusion proof audit path — PATH(m, D_n), RFC 9162 §2.1.3.1. */
export function inclusionPath(leafIndex: number, leafHashes: readonly Uint8Array[]): Buffer[] {
  const n = leafHashes.length;
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= n) {
    throw new Error(`leaf index ${leafIndex} out of range for tree size ${n}`);
  }
  return pathRec(leafIndex, leafHashes, 0, n);
}

function subProofRec(
  m: number,
  leafHashes: readonly Uint8Array[],
  lo: number,
  hi: number,
  isCompleteSubtree: boolean,
): Buffer[] {
  const n = hi - lo;
  if (m === n) return isCompleteSubtree ? [] : [subtreeRoot(leafHashes, lo, hi)];
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    return [
      ...subProofRec(m, leafHashes, lo, lo + k, isCompleteSubtree),
      subtreeRoot(leafHashes, lo + k, hi),
    ];
  }
  return [
    ...subProofRec(m - k, leafHashes, lo + k, hi, false),
    subtreeRoot(leafHashes, lo, lo + k),
  ];
}

/**
 * Consistency proof — PROOF(m, D_n) = SUBPROOF(m, D_n, true), RFC 9162
 * §2.1.4.1. Requires 0 < first < treeSize (DESIGN.md §9.2 parameter domain).
 */
export function consistencyPath(first: number, leafHashes: readonly Uint8Array[]): Buffer[] {
  const n = leafHashes.length;
  if (!Number.isInteger(first) || first <= 0 || first >= n) {
    throw new Error(`consistency proof requires 0 < first < treeSize (got ${first}, ${n})`);
  }
  return subProofRec(first, leafHashes, 0, n, true);
}

/** Inclusion proof verification — the iterative algorithm of RFC 9162 §2.1.3.2. */
export function verifyInclusion(input: {
  leafHash: Uint8Array;
  leafIndex: number;
  treeSize: number;
  auditPath: readonly Uint8Array[];
  rootHash: Uint8Array;
}): boolean {
  const { leafIndex, treeSize, auditPath } = input;
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return false;
  if (leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r: Buffer = Buffer.from(input.leafHash);
  for (const p of auditPath) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = hashChildren(p, r);
      if (fn % 2 === 0) {
        // right-shift fn and sn equally until LSB(fn) is set or fn is 0
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = hashChildren(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(Buffer.from(input.rootHash));
}

/** Consistency proof verification — the iterative algorithm of RFC 9162 §2.1.4.2. */
export function verifyConsistency(input: {
  first: number;
  second: number;
  firstRoot: Uint8Array;
  secondRoot: Uint8Array;
  consistencyPath: readonly Uint8Array[];
}): boolean {
  const { first, second } = input;
  if (!Number.isInteger(first) || !Number.isInteger(second)) return false;
  if (first <= 0 || first >= second) return false;
  if (input.consistencyPath.length === 0) return false;
  let path: Buffer[] = input.consistencyPath.map((p) => Buffer.from(p));
  if (isPowerOfTwo(first)) path = [Buffer.from(input.firstRoot), ...path];
  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr: Buffer = path[0];
  let sr: Buffer = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = hashChildren(c, fr);
      sr = hashChildren(c, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = hashChildren(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return (
    sn === 0 &&
    fr.equals(Buffer.from(input.firstRoot)) &&
    sr.equals(Buffer.from(input.secondRoot))
  );
}

// ---- `sha256:<hex>` JSON carrier helpers (DESIGN.md §7 / §9 wire format) ----

export function toPrefixedHash(hash: Uint8Array): string {
  return `sha256:${Buffer.from(hash).toString("hex")}`;
}

export function fromPrefixedHash(value: string): Buffer {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`expected "sha256:" + 64 lowercase hex, got: ${value}`);
  }
  return Buffer.from(value.slice("sha256:".length), "hex");
}

/** verifyInclusion over the §9.3 JSON carrier (prefixed-hex hashes). */
export function verifyInclusionProofJson(input: {
  leafHash: string;
  leafIndex: number;
  treeSize: number;
  auditPath: readonly string[];
  rootHash: string;
}): boolean {
  try {
    return verifyInclusion({
      leafHash: fromPrefixedHash(input.leafHash),
      leafIndex: input.leafIndex,
      treeSize: input.treeSize,
      auditPath: input.auditPath.map(fromPrefixedHash),
      rootHash: fromPrefixedHash(input.rootHash),
    });
  } catch {
    return false;
  }
}

/** verifyConsistency over the §9.2 JSON carrier (prefixed-hex hashes). */
export function verifyConsistencyProofJson(input: {
  first: number;
  second: number;
  firstRoot: string;
  secondRoot: string;
  consistencyPath: readonly string[];
}): boolean {
  try {
    return verifyConsistency({
      first: input.first,
      second: input.second,
      firstRoot: fromPrefixedHash(input.firstRoot),
      secondRoot: fromPrefixedHash(input.secondRoot),
      consistencyPath: input.consistencyPath.map(fromPrefixedHash),
    });
  } catch {
    return false;
  }
}
