/**
 * TransparencyLog — ties entry encoding (§4), the Merkle tree (§5), proofs
 * (§6) and STH signing (§7) together over a TlogStorage backend.
 *
 * Proofs are computed on demand from the leaf-hash range (DESIGN.md §14.1:
 * the tree is not materialized at phase-1 scale; MTH is a pure function).
 * JSON carriers match the §9 endpoint bodies so an HTTP layer can pass the
 * return values through verbatim.
 */

import { normalizeCertId } from "@jiaozi-protocol/gdid-core";
import {
  buildTlogEntry,
  encodeLeafInput,
  type TlogEntryV1,
  type TlogEventType,
} from "./entry.js";
import {
  consistencyPath,
  fromPrefixedHash,
  hashLeaf,
  inclusionPath,
  merkleRootFromLeafHashes,
  toPrefixedHash,
} from "./merkle.js";
import {
  buildSthPayload,
  signTreeHead,
  type SignedTreeHeadV1,
} from "./sth.js";
import type { StoredTlogEntry, TlogStorage } from "./storage.js";

export interface TlogSigningKey {
  privateKeyPkcs8Base64: string;
  publicKeyMultibase: string;
}

export interface AppendResult {
  leafIndex: number;
  entry: TlogEntryV1;
  /** "sha256:" + 64 hex leaf hash. */
  leafHash: string;
}

/** §9.3 response body. */
export interface InclusionProofJson {
  leafIndex: number;
  auditPath: string[];
}

/** §9.2 response body. */
export interface ConsistencyProofJson {
  consistencyPath: string[];
}

export class TransparencyLog {
  private readonly storage: TlogStorage;
  private readonly logId: string;
  private readonly signingKey?: TlogSigningKey;

  constructor(opts: { storage: TlogStorage; logId: string; signingKey?: TlogSigningKey }) {
    this.storage = opts.storage;
    this.logId = opts.logId;
    this.signingKey = opts.signingKey;
  }

  /**
   * Register one lifecycle event (issuer pipeline only — there is no public
   * submission per the §9 registration policy). certId normalization and
   * schema validation happen in buildTlogEntry.
   */
  async appendEvent(input: {
    eventType: TlogEventType;
    certId: string;
    contentHash: string;
    timestamp?: Date | string;
  }): Promise<AppendResult> {
    const entry = buildTlogEntry(input);
    const leafInput = encodeLeafInput(entry);
    const leafHash = hashLeaf(leafInput);
    const leafIndex = await this.storage.size();
    await this.storage.append({ leafIndex, entry, leafInput, leafHash });
    return { leafIndex, entry, leafHash: toPrefixedHash(leafHash) };
  }

  async treeSize(): Promise<number> {
    return this.storage.size();
  }

  /** MTH over the first treeSize leaves, as "sha256:<hex>". */
  async rootHashAt(treeSize: number): Promise<string> {
    const size = await this.storage.size();
    if (!Number.isInteger(treeSize) || treeSize < 0 || treeSize > size) {
      throw new Error(`treeSize ${treeSize} out of range (current size ${size})`);
    }
    const hashes = await this.storage.getLeafHashes(0, treeSize);
    return toPrefixedHash(merkleRootFromLeafHashes(hashes));
  }

  async currentRootHash(): Promise<string> {
    return this.rootHashAt(await this.storage.size());
  }

  /** Sign and persist an STH over the current tree (§7). */
  async signTreeHead(now?: Date): Promise<SignedTreeHeadV1> {
    if (!this.signingKey) throw new Error("no signing key configured");
    const treeSize = await this.storage.size();
    const payload = buildSthPayload({
      logId: this.logId,
      treeSize,
      rootHash: await this.rootHashAt(treeSize),
      now,
    });
    const sth = signTreeHead(
      payload,
      this.signingKey.privateKeyPkcs8Base64,
      this.signingKey.publicKeyMultibase,
    );
    await this.storage.storeSth(sth);
    return sth;
  }

  async latestSth(): Promise<SignedTreeHeadV1 | undefined> {
    return this.storage.getLatestSth();
  }

  /** §9.3 proof-by-hash: inclusion proof for a leaf hash under a given treeSize. */
  async inclusionProofByHash(leafHash: string, treeSize: number): Promise<InclusionProofJson> {
    const stored = await this.storage.findByLeafHash(fromPrefixedHash(leafHash));
    if (!stored) throw new Error(`unknown leaf hash: ${leafHash}`);
    return this.inclusionProofByIndex(stored.leafIndex, treeSize);
  }

  async inclusionProofByIndex(leafIndex: number, treeSize: number): Promise<InclusionProofJson> {
    const size = await this.storage.size();
    if (!Number.isInteger(treeSize) || treeSize < 1 || treeSize > size) {
      throw new Error(`treeSize ${treeSize} out of range (current size ${size})`);
    }
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
      throw new Error(`leafIndex ${leafIndex} not covered by treeSize ${treeSize}`);
    }
    const hashes = await this.storage.getLeafHashes(0, treeSize);
    return {
      leafIndex,
      auditPath: inclusionPath(leafIndex, hashes).map(toPrefixedHash),
    };
  }

  /** §9.2 sth-consistency: proof between two tree sizes (0 < first < second). */
  async consistencyProof(first: number, second: number): Promise<ConsistencyProofJson> {
    const size = await this.storage.size();
    if (
      !Number.isInteger(first) ||
      !Number.isInteger(second) ||
      first <= 0 ||
      second <= first ||
      second > size
    ) {
      throw new Error(
        `consistency proof requires 0 < first < second <= current size (got ${first}, ${second}, size ${size})`,
      );
    }
    const hashes = await this.storage.getLeafHashes(0, second);
    return { consistencyPath: consistencyPath(first, hashes).map(toPrefixedHash) };
  }

  /**
   * §9.4 entries: closed interval [start, end] like the REST endpoint,
   * optionally truncated via maxCount (the endpoint MAY truncate).
   */
  async getEntries(
    start: number,
    end: number,
    opts?: { maxCount?: number },
  ): Promise<Array<{ leafIndex: number; entry: TlogEntryV1 }>> {
    const size = await this.storage.size();
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end >= size) {
      throw new Error(`entry range [${start}, ${end}] out of bounds (size ${size})`);
    }
    let endExclusive = end + 1;
    if (opts?.maxCount !== undefined && opts.maxCount >= 1) {
      endExclusive = Math.min(endExclusive, start + opts.maxCount);
    }
    const range = await this.storage.getRange(start, endExclusive);
    return range.map((r: StoredTlogEntry) => ({ leafIndex: r.leafIndex, entry: r.entry }));
  }

  /** §9.5 convenience index: all leaf indexes for a cert id (input normalized). */
  async leafIndexesByCertId(certId: string): Promise<number[]> {
    return this.storage.findLeafIndexesByCertId(normalizeCertId(certId));
  }
}
