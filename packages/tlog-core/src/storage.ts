/**
 * Storage abstraction for the transparency log + in-memory implementation.
 *
 * Shape mirrors the phase-1 Postgres reference schema of DESIGN.md §14.1
 * (tlog_entries / tlog_sth): leaf input bytes are persisted verbatim to avoid
 * re-canonicalization ambiguity, leaf hashes are unique, appends are strictly
 * sequential, and STH storage rejects treeSize regressions. A production
 * (Postgres) implementation plugs in behind the same interface later.
 */

import type { TlogEntryV1 } from "./entry.js";
import type { SignedTreeHeadV1 } from "./sth.js";

export interface StoredTlogEntry {
  /** 0-based, dense, append order (§14.1 leaf_index). */
  leafIndex: number;
  entry: TlogEntryV1;
  /** Canonical JSON UTF-8 bytes, persisted verbatim (§14.1 leaf_input). */
  leafInput: Uint8Array;
  /** SHA-256(0x00 ‖ leafInput) (§14.1 leaf_hash, unique). */
  leafHash: Uint8Array;
}

export interface TlogStorage {
  /** Current number of leaves. */
  size(): Promise<number>;
  /**
   * Append one entry. MUST be called with record.leafIndex === size();
   * implementations MUST reject out-of-order appends and duplicate leaf
   * hashes (append-only discipline, §14.1).
   */
  append(record: StoredTlogEntry): Promise<void>;
  /** Entries in [start, endExclusive), ordered by leafIndex. */
  getRange(start: number, endExclusive: number): Promise<StoredTlogEntry[]>;
  /** Leaf hashes in [start, endExclusive), ordered by leafIndex. */
  getLeafHashes(start: number, endExclusive: number): Promise<Uint8Array[]>;
  /** Look up an entry by its leaf hash (§9.3 proof-by-hash). */
  findByLeafHash(leafHash: Uint8Array): Promise<StoredTlogEntry | undefined>;
  /** All leaf indexes recorded for a (normalized) cert id (§9.5 index). */
  findLeafIndexesByCertId(certId: string): Promise<number[]>;
  /** Latest stored STH, if any (§14.1 tlog_sth). */
  getLatestSth(): Promise<SignedTreeHeadV1 | undefined>;
  /** Store an STH; MUST reject treeSize regressions. */
  storeSth(sth: SignedTreeHeadV1): Promise<void>;
}

/** In-memory reference implementation (tests / vector generation / dev). */
export class MemoryTlogStorage implements TlogStorage {
  private entries: StoredTlogEntry[] = [];
  private byLeafHash = new Map<string, number>();
  private byCertId = new Map<string, number[]>();
  private sths: SignedTreeHeadV1[] = [];

  async size(): Promise<number> {
    return this.entries.length;
  }

  async append(record: StoredTlogEntry): Promise<void> {
    if (record.leafIndex !== this.entries.length) {
      throw new Error(
        `append-only violation: expected leafIndex ${this.entries.length}, got ${record.leafIndex}`,
      );
    }
    const hashKey = Buffer.from(record.leafHash).toString("hex");
    if (this.byLeafHash.has(hashKey)) {
      throw new Error(`duplicate leaf hash: sha256:${hashKey}`);
    }
    const stored: StoredTlogEntry = {
      leafIndex: record.leafIndex,
      entry: { ...record.entry },
      leafInput: Uint8Array.from(record.leafInput),
      leafHash: Uint8Array.from(record.leafHash),
    };
    this.entries.push(stored);
    this.byLeafHash.set(hashKey, stored.leafIndex);
    const list = this.byCertId.get(stored.entry.certId) ?? [];
    list.push(stored.leafIndex);
    this.byCertId.set(stored.entry.certId, list);
  }

  async getRange(start: number, endExclusive: number): Promise<StoredTlogEntry[]> {
    if (!Number.isInteger(start) || !Number.isInteger(endExclusive)) {
      throw new Error("range bounds must be integers");
    }
    if (start < 0 || endExclusive < start || endExclusive > this.entries.length) {
      throw new Error(`range [${start}, ${endExclusive}) out of bounds (size ${this.entries.length})`);
    }
    return this.entries.slice(start, endExclusive);
  }

  async getLeafHashes(start: number, endExclusive: number): Promise<Uint8Array[]> {
    const range = await this.getRange(start, endExclusive);
    return range.map((r) => r.leafHash);
  }

  async findByLeafHash(leafHash: Uint8Array): Promise<StoredTlogEntry | undefined> {
    const idx = this.byLeafHash.get(Buffer.from(leafHash).toString("hex"));
    return idx === undefined ? undefined : this.entries[idx];
  }

  async findLeafIndexesByCertId(certId: string): Promise<number[]> {
    return [...(this.byCertId.get(certId) ?? [])];
  }

  async getLatestSth(): Promise<SignedTreeHeadV1 | undefined> {
    return this.sths.length === 0 ? undefined : this.sths[this.sths.length - 1];
  }

  async storeSth(sth: SignedTreeHeadV1): Promise<void> {
    const latest = await this.getLatestSth();
    if (latest && sth.payload.treeSize < latest.payload.treeSize) {
      throw new Error(
        `STH treeSize regression: ${sth.payload.treeSize} < ${latest.payload.treeSize}`,
      );
    }
    this.sths.push(sth);
  }
}
