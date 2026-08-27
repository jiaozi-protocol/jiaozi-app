import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { generateEd25519Keypair } from "@jiaozi-protocol/gdid-core";
import { entryLeafHash } from "./entry.js";
import { verifyConsistencyProofJson, verifyInclusionProofJson } from "./merkle.js";
import { verifySignedTreeHead } from "./sth.js";
import { MemoryTlogStorage } from "./storage.js";
import { TransparencyLog, type TlogSigningKey } from "./log.js";

const LOG_ID = "https://www.jiaozi.io/api/tlog";
const key = generateEd25519Keypair();
const signingKey: TlogSigningKey = {
  privateKeyPkcs8Base64: key.privateKeyPkcs8Base64,
  publicKeyMultibase: key.publicKeyMultibase,
};

function detailHash(seed: string): string {
  return `sha256:${createHash("sha256").update(seed).digest("hex")}`;
}

const EVENTS = [
  { eventType: "cert_issued", certId: "JIAOZI-2026-000001" },
  { eventType: "cert_issued", certId: "JIAOZI-2026-000002" },
  { eventType: "cert_suspended", certId: "JIAOZI-2026-000001" },
  { eventType: "cert_reinstated", certId: "JIAOZI-2026-000001" },
  { eventType: "cert_issued", certId: "JP-2026-000003" },
  { eventType: "cert_revoked", certId: "JIAOZI-2026-000002" },
  { eventType: "cert_issued", certId: "JJ-2026-000004" },
  { eventType: "cert_revoked", certId: "JIAOZI-2026-000001" },
] as const;

async function buildLog(): Promise<TransparencyLog> {
  const log = new TransparencyLog({ storage: new MemoryTlogStorage(), logId: LOG_ID, signingKey });
  for (let i = 0; i < EVENTS.length; i++) {
    await log.appendEvent({
      ...EVENTS[i],
      contentHash: detailHash(`detail-${i}`),
      timestamp: new Date(Date.parse("2026-08-08T00:00:00.000Z") + i * 1000),
    });
  }
  return log;
}

test("append assigns dense 0-based leaf indexes and normalizes cert ids", async () => {
  const log = new TransparencyLog({ storage: new MemoryTlogStorage(), logId: LOG_ID });
  const first = await log.appendEvent({
    eventType: "cert_issued",
    certId: "jj-2026-000004",
    contentHash: detailHash("x"),
    timestamp: "2026-08-08T00:00:00.000Z",
  });
  assert.equal(first.leafIndex, 0);
  assert.equal(first.entry.certId, "JP-2026-000004");
  assert.equal(entryLeafHash(first.entry).toString("hex"), first.leafHash.slice("sha256:".length));
  assert.equal(await log.treeSize(), 1);
});

test("empty log root is the empty-string hash; STH signs and verifies", async () => {
  const log = new TransparencyLog({ storage: new MemoryTlogStorage(), logId: LOG_ID, signingKey });
  assert.equal(
    await log.currentRootHash(),
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  const sth = await log.signTreeHead(new Date("2026-08-08T00:01:00.000Z"));
  assert.equal(sth.payload.treeSize, 0);
  assert.equal(verifySignedTreeHead(sth, { trustedKeys: [key.publicKeyMultibase] }).valid, true);
  assert.deepEqual(await log.latestSth(), sth);
});

test("inclusion proofs from the log verify against the root (all leaves, several sizes)", async () => {
  const log = await buildLog();
  for (const treeSize of [1, 3, 5, 8]) {
    const root = await log.rootHashAt(treeSize);
    for (let i = 0; i < treeSize; i++) {
      const { leafIndex, auditPath } = await log.inclusionProofByIndex(i, treeSize);
      const [{ entry }] = await log.getEntries(i, i);
      assert.ok(
        verifyInclusionProofJson({
          leafHash: `sha256:${entryLeafHash(entry).toString("hex")}`,
          leafIndex,
          treeSize,
          auditPath,
          rootHash: root,
        }),
        `leaf ${i} @ size ${treeSize}`,
      );
    }
  }
});

test("inclusion proof by leaf hash finds the right index", async () => {
  const log = await buildLog();
  const [{ entry }] = await log.getEntries(5, 5);
  const leafHash = `sha256:${entryLeafHash(entry).toString("hex")}`;
  const proof = await log.inclusionProofByHash(leafHash, 8);
  assert.equal(proof.leafIndex, 5);
  assert.ok(
    verifyInclusionProofJson({
      leafHash,
      leafIndex: proof.leafIndex,
      treeSize: 8,
      auditPath: proof.auditPath,
      rootHash: await log.rootHashAt(8),
    }),
  );
  await assert.rejects(log.inclusionProofByHash(`sha256:${"00".repeat(32)}`, 8));
});

test("consistency proofs between all size pairs verify", async () => {
  const log = await buildLog();
  const roots: string[] = [];
  for (let n = 0; n <= 8; n++) roots[n] = await log.rootHashAt(n);
  for (let second = 2; second <= 8; second++) {
    for (let first = 1; first < second; first++) {
      const { consistencyPath } = await log.consistencyProof(first, second);
      assert.ok(
        verifyConsistencyProofJson({
          first,
          second,
          firstRoot: roots[first],
          secondRoot: roots[second],
          consistencyPath,
        }),
        `consistency (${first}, ${second})`,
      );
    }
  }
});

test("proof and range parameter domains are enforced", async () => {
  const log = await buildLog();
  await assert.rejects(log.inclusionProofByIndex(0, 0));
  await assert.rejects(log.inclusionProofByIndex(8, 8));
  await assert.rejects(log.inclusionProofByIndex(5, 3));
  await assert.rejects(log.consistencyProof(0, 5));
  await assert.rejects(log.consistencyProof(5, 5));
  await assert.rejects(log.consistencyProof(1, 9));
  await assert.rejects(log.getEntries(-1, 2));
  await assert.rejects(log.getEntries(0, 8));
  await assert.rejects(log.rootHashAt(9));
});

test("getEntries returns the closed interval and honors truncation", async () => {
  const log = await buildLog();
  const all = await log.getEntries(0, 7);
  assert.equal(all.length, 8);
  assert.deepEqual(
    all.map((e) => e.leafIndex),
    [0, 1, 2, 3, 4, 5, 6, 7],
  );
  const truncated = await log.getEntries(2, 7, { maxCount: 3 });
  assert.deepEqual(
    truncated.map((e) => e.leafIndex),
    [2, 3, 4],
  );
});

test("per-cert index covers all events and normalizes queries (§9.5)", async () => {
  const log = await buildLog();
  assert.deepEqual(await log.leafIndexesByCertId("JIAOZI-2026-000001"), [0, 2, 3, 7]);
  assert.deepEqual(await log.leafIndexesByCertId("jiaozi-2026-000002"), [1, 5]);
  // JJ input was normalized to JP at write time; JJ query must find it too
  assert.deepEqual(await log.leafIndexesByCertId("JJ-2026-000004"), [6]);
  assert.deepEqual(await log.leafIndexesByCertId("JIAOZI-2099-999999"), []);
});

test("storage enforces append-only discipline", async () => {
  const storage = new MemoryTlogStorage();
  const log = new TransparencyLog({ storage, logId: LOG_ID });
  const res = await log.appendEvent({
    eventType: "cert_issued",
    certId: "JIAOZI-2026-000001",
    contentHash: detailHash("a"),
    timestamp: "2026-08-08T00:00:00.000Z",
  });
  // duplicate identical entry => identical leaf hash => rejected
  await assert.rejects(
    log.appendEvent({
      eventType: "cert_issued",
      certId: "JIAOZI-2026-000001",
      contentHash: detailHash("a"),
      timestamp: "2026-08-08T00:00:00.000Z",
    }),
    /duplicate leaf hash/,
  );
  // out-of-order manual append rejected
  const stored = (await storage.getRange(0, 1))[0];
  await assert.rejects(
    storage.append({ ...stored, leafIndex: 5, leafHash: Buffer.alloc(32, 1) }),
    /append-only violation/,
  );
  assert.equal(res.leafIndex, 0);
});

test("STH storage rejects treeSize regressions; unsigned logs cannot sign", async () => {
  const storage = new MemoryTlogStorage();
  const log = new TransparencyLog({ storage, logId: LOG_ID, signingKey });
  await log.appendEvent({
    eventType: "cert_issued",
    certId: "JIAOZI-2026-000001",
    contentHash: detailHash("a"),
    timestamp: "2026-08-08T00:00:00.000Z",
  });
  const sth1 = await log.signTreeHead(new Date("2026-08-08T00:01:00.000Z"));
  await assert.rejects(
    storage.storeSth({ ...sth1, payload: { ...sth1.payload, treeSize: 0 } }),
    /regression/,
  );
  const unsigned = new TransparencyLog({ storage: new MemoryTlogStorage(), logId: LOG_ID });
  await assert.rejects(unsigned.signTreeHead(), /no signing key/);
});
