// Deterministic test vectors for jiaozi.tlog.v1 (standards/tlog-v1/DESIGN.md).
// Fixed Ed25519 seed + fixed clock => stable bytes across runs.
// Organization mirrors standards/status-v1 (generator + zero-dep conformance runner).
// Usage: node --import tsx packages/tlog-core/vectors/generate-vectors.mjs
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MemoryTlogStorage,
  TransparencyLog,
  entryLeafHash,
  canonicalEntryJson,
  verifyConsistencyProofJson,
  verifyInclusionProofJson,
  verifySignedTreeHead,
} from "../src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));

// Fixed 32-byte seed (test-only key; NEVER use for anything real).
// Distinct from the status.v1 vector seed (0x07) to avoid key confusion.
const seed = Buffer.alloc(32, 0x2a);
const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
const privateKeyPkcs8Base64 = pkcs8.toString("base64");
const spki = createPublicKey(
  createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }),
).export({ format: "der", type: "spki" });
const publicKeyMultibase = "z" + spki.subarray(spki.length - 32).toString("base64url");

const LOG_ID = "https://www.jiaozi.io/api/tlog";
const T0 = Date.parse("2026-08-08T00:00:00.000Z");

const detailHash = (seedText) =>
  `sha256:${createHash("sha256").update(seedText).digest("hex")}`;

// 8 lifecycle events covering all four types plus both legacy prefixes
// (input "JJ-2026-000004" MUST normalize to "JP-2026-000004" per §4.2).
const EVENT_INPUTS = [
  { eventType: "cert_issued", certId: "JIAOZI-2026-000001" },
  { eventType: "cert_issued", certId: "JIAOZI-2026-000002" },
  { eventType: "cert_suspended", certId: "JIAOZI-2026-000001" },
  { eventType: "cert_reinstated", certId: "JIAOZI-2026-000001" },
  { eventType: "cert_issued", certId: "JP-2026-000003" },
  { eventType: "cert_revoked", certId: "JIAOZI-2026-000002" },
  { eventType: "cert_issued", certId: "JJ-2026-000004" },
  { eventType: "cert_revoked", certId: "JIAOZI-2026-000001" },
];

const log = new TransparencyLog({
  storage: new MemoryTlogStorage(),
  logId: LOG_ID,
  signingKey: { privateKeyPkcs8Base64, publicKeyMultibase },
});

const entries = [];
for (let i = 0; i < EVENT_INPUTS.length; i++) {
  const res = await log.appendEvent({
    ...EVENT_INPUTS[i],
    contentHash: detailHash(`tlog-vector-detail-${i}`),
    timestamp: new Date(T0 + i * 1000),
  });
  entries.push({
    leafIndex: res.leafIndex,
    entry: res.entry,
    canonicalEntry: canonicalEntryJson(res.entry),
    leafHash: res.leafHash,
  });
}

const N = entries.length;

// Tree heads for every prefix size 0..N (root recomputation targets).
const treeHeads = [];
for (let n = 0; n <= N; n++) {
  treeHeads.push({ treeSize: n, rootHash: await log.rootHashAt(n) });
}
const rootAt = (n) => treeHeads[n].rootHash;

// ---- inclusion proof vectors (§6.1 / §9.3 carrier) ----
const inclusionVectors = [];
for (let i = 0; i < N; i++) {
  const { auditPath } = await log.inclusionProofByIndex(i, N);
  inclusionVectors.push({
    name: `inclusion-leaf${i}-size${N}`,
    description: `Leaf ${i} under the size-${N} tree head. MUST verify.`,
    leafIndex: i,
    treeSize: N,
    leafHash: entries[i].leafHash,
    auditPath,
    rootHash: rootAt(N),
    expect: { valid: true },
  });
}
for (const [i, n] of [[0, 1], [2, 5], [4, 6]]) {
  const { auditPath } = await log.inclusionProofByIndex(i, n);
  inclusionVectors.push({
    name: `inclusion-leaf${i}-size${n}`,
    description: `Leaf ${i} under the intermediate size-${n} tree head. MUST verify.`,
    leafIndex: i,
    treeSize: n,
    leafHash: entries[i].leafHash,
    auditPath,
    rootHash: rootAt(n),
    expect: { valid: true },
  });
}
{
  const { auditPath } = await log.inclusionProofByIndex(3, N);
  inclusionVectors.push({
    name: "inclusion-tampered-path",
    description: "First audit-path node corrupted. MUST fail.",
    leafIndex: 3,
    treeSize: N,
    leafHash: entries[3].leafHash,
    auditPath: [`sha256:${"55".repeat(32)}`, ...auditPath.slice(1)],
    rootHash: rootAt(N),
    expect: { valid: false },
  });
  inclusionVectors.push({
    name: "inclusion-wrong-index",
    description: "Audit path of leaf 3 presented for leaf 4. MUST fail.",
    leafIndex: 4,
    treeSize: N,
    leafHash: entries[3].leafHash,
    auditPath,
    rootHash: rootAt(N),
    expect: { valid: false },
  });
  inclusionVectors.push({
    name: "inclusion-wrong-root",
    description: "Proof checked against the size-7 root instead of size-8. MUST fail.",
    leafIndex: 3,
    treeSize: N,
    leafHash: entries[3].leafHash,
    auditPath,
    rootHash: rootAt(N - 1),
    expect: { valid: false },
  });
}

// ---- consistency proof vectors (§6.2 / §9.2 carrier) ----
const consistencyVectors = [];
for (const [first, second] of [[1, 2], [1, 8], [2, 5], [3, 7], [4, 8], [6, 7], [7, 8]]) {
  const { consistencyPath } = await log.consistencyProof(first, second);
  consistencyVectors.push({
    name: `consistency-${first}-${second}`,
    description: `Size-${first} tree is a prefix of the size-${second} tree. MUST verify.`,
    first,
    second,
    firstRoot: rootAt(first),
    secondRoot: rootAt(second),
    consistencyPath,
    expect: { valid: true },
  });
}
{
  const { consistencyPath } = await log.consistencyProof(3, 8);
  consistencyVectors.push({
    name: "consistency-tampered-path",
    description: "First consistency node corrupted. MUST fail.",
    first: 3,
    second: 8,
    firstRoot: rootAt(3),
    secondRoot: rootAt(8),
    consistencyPath: [`sha256:${"66".repeat(32)}`, ...consistencyPath.slice(1)],
    expect: { valid: false },
  });
  consistencyVectors.push({
    name: "consistency-rewritten-history",
    description:
      "Old root replaced by a different tree's root (history rewrite). MUST fail.",
    first: 3,
    second: 8,
    firstRoot: rootAt(4),
    secondRoot: rootAt(8),
    consistencyPath,
    expect: { valid: false },
  });
}

// ---- STH vectors (§7 shell) ----
const sth = await log.signTreeHead(new Date(T0 + 60_000));
const sthVectors = [
  {
    name: "sth-valid",
    description: "Well-formed STH over the size-8 tree. MUST verify.",
    sth,
    verifyOptions: { trustedKeys: [publicKeyMultibase], expectedLogId: LOG_ID },
    expect: { valid: true },
  },
  {
    name: "sth-tampered-tree-size",
    description: "treeSize bumped after signing. MUST fail: bad_signature.",
    sth: { ...sth, payload: { ...sth.payload, treeSize: 9 } },
    expect: { valid: false, reason: "bad_signature" },
  },
  {
    name: "sth-tampered-root",
    description: "rootHash replaced after signing. MUST fail: bad_signature.",
    sth: { ...sth, payload: { ...sth.payload, rootHash: `sha256:${"77".repeat(32)}` } },
    expect: { valid: false, reason: "bad_signature" },
  },
  {
    name: "sth-untrusted-key",
    description: "RP pins a different log key. MUST fail: untrusted_key.",
    sth,
    verifyOptions: { trustedKeys: ["zSOME-OTHER-KEY"] },
    expect: { valid: false, reason: "untrusted_key" },
  },
  {
    name: "sth-tree-size-regression",
    description: "RP has already accepted treeSize 9. MUST fail: tree_size_regression.",
    sth,
    verifyOptions: { minTreeSize: 9 },
    expect: { valid: false, reason: "tree_size_regression" },
  },
  {
    name: "sth-log-id-mismatch",
    description: "RP expects a different logId. MUST fail: log_id_mismatch.",
    sth,
    verifyOptions: { expectedLogId: "https://evil.example/api/tlog" },
    expect: { valid: false, reason: "log_id_mismatch" },
  },
];

// ---- self-check against the reference implementation before writing ----
let failures = 0;
const check = (name, got, want) => {
  const ok = got.valid === want.valid && (want.valid || !want.reason || got.reason === want.reason);
  if (!ok) {
    console.error("SELF-CHECK FAILED:", name, "got", got, "expected", want);
    failures++;
  } else {
    console.log("self-check ok:", name);
  }
};
for (const v of inclusionVectors) {
  check(v.name, { valid: verifyInclusionProofJson(v) }, v.expect);
}
for (const v of consistencyVectors) {
  check(v.name, { valid: verifyConsistencyProofJson(v) }, v.expect);
}
for (const v of sthVectors) {
  check(v.name, verifySignedTreeHead(v.sth, v.verifyOptions), v.expect);
}
for (const e of entries) {
  const recomputed = `sha256:${entryLeafHash(e.entry).toString("hex")}`;
  check(`${e.name ?? `entry-${e.leafIndex}`}-leaf-hash`, { valid: recomputed === e.leafHash }, { valid: true });
}
if (failures > 0) process.exit(1);

const out = {
  schema: "jiaozi.tlog.v1",
  design: "standards/tlog-v1/DESIGN.md (v1.0-design.1, public review until 2026-08-18)",
  generated: "deterministic (fixed seed, fixed clock 2026-08-08T00:00:00Z)",
  signingKey: {
    note: "TEST KEY ONLY - seed is 32 bytes of 0x2a",
    privateKeyPkcs8Base64,
    publicKeyMultibase,
  },
  logId: LOG_ID,
  entries,
  treeHeads,
  sth,
  vectors: {
    inclusion: inclusionVectors,
    consistency: consistencyVectors,
    sth: sthVectors,
  },
};
writeFileSync(join(here, "test-vectors.json"), JSON.stringify(out, null, 2) + "\n");
console.log(
  "wrote test-vectors.json:",
  entries.length,
  "entries,",
  treeHeads.length,
  "tree heads,",
  inclusionVectors.length + consistencyVectors.length + sthVectors.length,
  "proof/STH vectors",
);
