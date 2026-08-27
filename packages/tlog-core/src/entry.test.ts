import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  buildTlogEntry,
  canonicalEntryJson,
  encodeLeafInput,
  entryLeafHash,
  isTlogEntryV1,
  validateTlogEntryV1,
  type TlogEntryV1,
} from "./entry.js";

const DETAIL_HASH = `sha256:${createHash("sha256").update("detail-0").digest("hex")}`;

function sampleEntry(): TlogEntryV1 {
  return buildTlogEntry({
    eventType: "cert_issued",
    certId: "JIAOZI-2026-000001",
    contentHash: DETAIL_HASH,
    timestamp: "2026-08-08T00:00:00.000Z",
  });
}

test("canonical JSON sorts keys and has no whitespace (JCS on string fields)", () => {
  const canonical = canonicalEntryJson(sampleEntry());
  assert.equal(
    canonical,
    `{"certId":"JIAOZI-2026-000001","contentHash":"${DETAIL_HASH}",` +
      `"eventType":"cert_issued","schema":"jiaozi.tlog.v1",` +
      `"timestamp":"2026-08-08T00:00:00.000Z"}`,
  );
});

test("leaf input is UTF-8 of canonical JSON; leaf hash is SHA-256(0x00 || input)", () => {
  const entry = sampleEntry();
  const input = encodeLeafInput(entry);
  assert.deepEqual(input, Buffer.from(canonicalEntryJson(entry), "utf8"));
  const expected = createHash("sha256")
    .update(Buffer.from([0x00]))
    .update(input)
    .digest();
  assert.deepEqual(entryLeafHash(entry), expected);
});

test("buildTlogEntry normalizes cert ids (JJ -> JP, uppercase) and content hash", () => {
  const entry = buildTlogEntry({
    eventType: "cert_revoked",
    certId: "jj-2026-000007",
    contentHash: DETAIL_HASH.slice("sha256:".length).toUpperCase(),
    timestamp: new Date("2026-08-08T00:00:01.000Z"),
  });
  assert.equal(entry.certId, "JP-2026-000007");
  assert.equal(entry.contentHash, DETAIL_HASH);
  assert.equal(entry.timestamp, "2026-08-08T00:00:01.000Z");
});

test("all four event types are accepted", () => {
  for (const eventType of ["cert_issued", "cert_suspended", "cert_reinstated", "cert_revoked"] as const) {
    const entry = buildTlogEntry({
      eventType,
      certId: "JIAOZI-2026-000001",
      contentHash: DETAIL_HASH,
      timestamp: "2026-08-08T00:00:00.000Z",
    });
    assert.ok(isTlogEntryV1(entry));
  }
});

test("validation rejects malformed entries", () => {
  const base = sampleEntry();
  assert.equal(validateTlogEntryV1(null), "not_an_object");
  assert.equal(validateTlogEntryV1([base]), "not_an_object");
  assert.equal(validateTlogEntryV1({ ...base, extra: 1 }), "extra_field");
  assert.equal(validateTlogEntryV1({ ...base, schema: "jiaozi.tlog.v2" }), "bad_schema");
  assert.equal(validateTlogEntryV1({ ...base, eventType: "cert_renewed" }), "bad_event_type");
  assert.equal(validateTlogEntryV1({ ...base, certId: "jiaozi-2026-000001" }), "bad_cert_id");
  assert.equal(validateTlogEntryV1({ ...base, certId: "JJ-2026-000001" }), "bad_cert_id");
  assert.equal(validateTlogEntryV1({ ...base, timestamp: "2026-08-08T00:00:00Z" }), "bad_timestamp");
  assert.equal(validateTlogEntryV1({ ...base, timestamp: "2026-13-40T00:00:00.000Z" }), "bad_timestamp");
  assert.equal(
    validateTlogEntryV1({ ...base, contentHash: DETAIL_HASH.toUpperCase() }),
    "bad_content_hash",
  );
  assert.equal(validateTlogEntryV1({ ...base, contentHash: "sha256:abc" }), "bad_content_hash");
  assert.equal(validateTlogEntryV1(base), null);
});

test("buildTlogEntry throws on invalid inputs", () => {
  assert.throws(() =>
    buildTlogEntry({
      eventType: "cert_issued",
      certId: "NOT-A-CERT",
      contentHash: DETAIL_HASH,
      timestamp: "2026-08-08T00:00:00.000Z",
    }),
  );
  assert.throws(() =>
    buildTlogEntry({
      eventType: "cert_issued",
      certId: "JIAOZI-2026-000001",
      contentHash: "md5:whatever",
      timestamp: "2026-08-08T00:00:00.000Z",
    }),
  );
});
