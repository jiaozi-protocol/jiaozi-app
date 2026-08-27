import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson, generateEd25519Keypair, verifyWithMultibase } from "@jiaozi-protocol/gdid-core";
import {
  buildSthPayload,
  isSignedTreeHeadV1,
  signTreeHead,
  verifySignedTreeHead,
} from "./sth.js";

const LOG_ID = "https://www.jiaozi.io/api/tlog";
const ROOT = `sha256:${"ab".repeat(32)}`;
const key = generateEd25519Keypair();

function makeSth(treeSize = 8) {
  const payload = buildSthPayload({
    logId: LOG_ID,
    treeSize,
    rootHash: ROOT,
    now: new Date("2026-08-08T00:01:00.000Z"),
  });
  return signTreeHead(payload, key.privateKeyPkcs8Base64, key.publicKeyMultibase);
}

test("STH payload fields follow DESIGN.md §7", () => {
  const sth = makeSth();
  assert.deepEqual(sth.payload, {
    schema: "jiaozi.tlog-sth.v1",
    logId: LOG_ID,
    treeSize: 8,
    timestamp: "2026-08-08T00:01:00.000Z",
    rootHash: ROOT,
  });
  assert.ok(isSignedTreeHeadV1(sth));
});

test("buildSthPayload accepts raw 32-byte roots and rejects bad inputs", () => {
  const raw = Buffer.alloc(32, 0xab);
  const payload = buildSthPayload({ logId: LOG_ID, treeSize: 0, rootHash: raw });
  assert.equal(payload.rootHash, ROOT);
  assert.throws(() => buildSthPayload({ logId: LOG_ID, treeSize: -1, rootHash: ROOT }));
  assert.throws(() => buildSthPayload({ logId: LOG_ID, treeSize: 1.5, rootHash: ROOT }));
  assert.throws(() => buildSthPayload({ logId: LOG_ID, treeSize: 1, rootHash: "sha256:xyz" }));
});

test("valid STH verifies (also with key pin and log id pin)", () => {
  const sth = makeSth();
  assert.deepEqual(verifySignedTreeHead(sth), { valid: true, payload: sth.payload });
  const pinned = verifySignedTreeHead(sth, {
    trustedKeys: [key.publicKeyMultibase],
    expectedLogId: LOG_ID,
    minTreeSize: 8,
  });
  assert.equal(pinned.valid, true);
});

test("signature shell is byte-compatible with the status.v1 verification path", () => {
  const sth = makeSth();
  assert.ok(verifyWithMultibase(sth.publicKeyMultibase, canonicalJson(sth.payload), sth.signature));
});

test("tampered payload fails with bad_signature", () => {
  const sth = makeSth();
  const tampered = { ...sth, payload: { ...sth.payload, treeSize: 9 } };
  assert.deepEqual(verifySignedTreeHead(tampered), { valid: false, reason: "bad_signature" });
});

test("untrusted key / log id mismatch / treeSize regression are rejected", () => {
  const sth = makeSth();
  assert.deepEqual(verifySignedTreeHead(sth, { trustedKeys: ["zSOME-OTHER-KEY"] }), {
    valid: false,
    reason: "untrusted_key",
  });
  assert.deepEqual(verifySignedTreeHead(sth, { expectedLogId: "https://evil.example" }), {
    valid: false,
    reason: "log_id_mismatch",
  });
  assert.deepEqual(verifySignedTreeHead(sth, { minTreeSize: 9 }), {
    valid: false,
    reason: "tree_size_regression",
  });
});

test("malformed STHs fail with bad_shape", () => {
  assert.deepEqual(verifySignedTreeHead(null), { valid: false, reason: "bad_shape" });
  assert.deepEqual(verifySignedTreeHead({}), { valid: false, reason: "bad_shape" });
  const sth = makeSth();
  const noRoot = { ...sth, payload: { ...sth.payload, rootHash: "0xdeadbeef" } };
  assert.deepEqual(verifySignedTreeHead(noRoot), { valid: false, reason: "bad_shape" });
  const fracSize = { ...sth, payload: { ...sth.payload, treeSize: 1.5 } };
  assert.deepEqual(verifySignedTreeHead(fracSize), { valid: false, reason: "bad_shape" });
});
