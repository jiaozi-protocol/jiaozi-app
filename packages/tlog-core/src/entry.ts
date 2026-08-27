/**
 * jiaozi.tlog.v1 log entry — schema, validation, canonical (JCS) encoding,
 * leaf input bytes and leaf hash. Design: standards/tlog-v1/DESIGN.md §4–§5.
 *
 * Canonical serialization reuses gdid-core `canonicalJson` (recursive key sort +
 * JSON.stringify), which is byte-identical to RFC 8785 JCS on this schema's
 * field domain (all values are string literals) — DESIGN.md §4.3.
 */

import { asSha256Prefixed, canonicalJson, normalizeCertId } from "@jiaozi-protocol/gdid-core";
import { hashLeaf } from "./merkle.js";

export const TLOG_SCHEMA = "jiaozi.tlog.v1" as const;

/** DESIGN.md §4.1 — the four credential lifecycle event types (closed set). */
export const TLOG_EVENT_TYPES = [
  "cert_issued",
  "cert_suspended",
  "cert_reinstated",
  "cert_revoked",
] as const;

export type TlogEventType = (typeof TLOG_EVENT_TYPES)[number];

/** DESIGN.md §4.2 — exactly these five fields, no extras allowed. */
export interface TlogEntryV1 {
  schema: typeof TLOG_SCHEMA;
  eventType: TlogEventType;
  certId: string;
  timestamp: string;
  contentHash: string;
}

/** §4.2: cert id after normalizeCertId — JIAOZI or JP prefix (JJ is folded into JP). */
const CERT_ID_RE = /^(JIAOZI|JP)-\d{4}-\d{6,9}$/;
/** §4.2: RFC 3339 UTC with millisecond precision (exactly what Date#toISOString emits). */
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CONTENT_HASH_RE = /^sha256:[0-9a-f]{64}$/;

const ENTRY_FIELDS = ["schema", "eventType", "certId", "timestamp", "contentHash"] as const;

export type TlogEntryValidationError =
  | "not_an_object"
  | "extra_field"
  | "bad_schema"
  | "bad_event_type"
  | "bad_cert_id"
  | "bad_timestamp"
  | "bad_content_hash";

/** Structural validation per §4.2. Returns null when valid. */
export function validateTlogEntryV1(value: unknown): TlogEntryValidationError | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "not_an_object";
  const v = value as Record<string, unknown>;
  for (const key of Object.keys(v)) {
    if (!(ENTRY_FIELDS as readonly string[]).includes(key)) return "extra_field";
  }
  if (v.schema !== TLOG_SCHEMA) return "bad_schema";
  if (!TLOG_EVENT_TYPES.includes(v.eventType as TlogEventType)) return "bad_event_type";
  if (typeof v.certId !== "string" || !CERT_ID_RE.test(v.certId)) return "bad_cert_id";
  if (
    typeof v.timestamp !== "string" ||
    !TIMESTAMP_RE.test(v.timestamp) ||
    Number.isNaN(Date.parse(v.timestamp))
  ) {
    return "bad_timestamp";
  }
  if (typeof v.contentHash !== "string" || !CONTENT_HASH_RE.test(v.contentHash)) {
    return "bad_content_hash";
  }
  return null;
}

export function isTlogEntryV1(value: unknown): value is TlogEntryV1 {
  return validateTlogEntryV1(value) === null;
}

export function assertTlogEntryV1(value: unknown): asserts value is TlogEntryV1 {
  const err = validateTlogEntryV1(value);
  if (err) throw new Error(`invalid jiaozi.tlog.v1 entry: ${err}`);
}

/**
 * Build a well-formed entry from raw inputs: certId is normalized (§4.2 MUST,
 * JJ- → JP-, uppercase), contentHash is normalized to `sha256:<hex>` and the
 * timestamp defaults to "now" (the log's reception time, §4.2).
 */
export function buildTlogEntry(input: {
  eventType: TlogEventType;
  certId: string;
  contentHash: string;
  /** Log reception time; defaults to new Date(). */
  timestamp?: Date | string;
}): TlogEntryV1 {
  const ts =
    input.timestamp === undefined
      ? new Date().toISOString()
      : typeof input.timestamp === "string"
        ? input.timestamp
        : input.timestamp.toISOString();
  const entry: TlogEntryV1 = {
    schema: TLOG_SCHEMA,
    eventType: input.eventType,
    certId: normalizeCertId(input.certId),
    timestamp: ts,
    contentHash: asSha256Prefixed(input.contentHash),
  };
  assertTlogEntryV1(entry);
  return entry;
}

/** Canonical JSON string of a validated entry (§4.3). */
export function canonicalEntryJson(entry: TlogEntryV1): string {
  assertTlogEntryV1(entry);
  return canonicalJson(entry);
}

/** Leaf input bytes = UTF-8 of the canonical JSON (§4.3). */
export function encodeLeafInput(entry: TlogEntryV1): Buffer {
  return Buffer.from(canonicalEntryJson(entry), "utf8");
}

/** Leaf hash = SHA-256(0x00 ‖ leaf input) (§5), as raw bytes. */
export function entryLeafHash(entry: TlogEntryV1): Buffer {
  return hashLeaf(encodeLeafInput(entry));
}
