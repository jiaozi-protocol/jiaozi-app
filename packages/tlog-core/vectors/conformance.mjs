#!/usr/bin/env node
// jiaozi.tlog.v1 conformance tester — the referee.
// Zero dependencies; independent verifier implementation (does NOT import
// tlog-core or gdid-core, so a bug in the reference implementation cannot
// hide itself). Organization mirrors standards/status-v1/conformance.mjs.
//
// Usage: node packages/tlog-core/vectors/conformance.mjs
import { createHash, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0;
let fail = 0;

function ok(name, detail = "") {
  pass++;
  console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ""}`);
}
function bad(name, detail = "") {
  fail++;
  console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`);
}

// ---- independent implementation of DESIGN.md §4–§7 ----

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const hashLeaf = (input) => sha256(Buffer.from([0x00]), input);
const hashChildren = (l, r) => sha256(Buffer.from([0x01]), l, r);
const unhex = (s) => {
  if (!/^sha256:[0-9a-f]{64}$/.test(s)) throw new Error(`bad hash carrier: ${s}`);
  return Buffer.from(s.slice(7), "hex");
};
const hex = (b) => `sha256:${b.toString("hex")}`;

function largestPowerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// RFC 9162 §2.1.1 MTH over leaf hashes
function mth(hashes, lo = 0, hi = hashes.length) {
  const n = hi - lo;
  if (n === 0) return sha256();
  if (n === 1) return hashes[lo];
  const k = largestPowerOfTwoBelow(n);
  return hashChildren(mth(hashes, lo, lo + k), mth(hashes, lo + k, hi));
}

// RFC 9162 §2.1.3.1 PATH
function path(m, hashes, lo = 0, hi = hashes.length) {
  const n = hi - lo;
  if (n === 1) return [];
  const k = largestPowerOfTwoBelow(n);
  return m < k
    ? [...path(m, hashes, lo, lo + k), mth(hashes, lo + k, hi)]
    : [...path(m - k, hashes, lo + k, hi), mth(hashes, lo, lo + k)];
}

// RFC 9162 §2.1.4.1 PROOF / SUBPROOF
function subproof(m, hashes, lo, hi, b) {
  const n = hi - lo;
  if (m === n) return b ? [] : [mth(hashes, lo, hi)];
  const k = largestPowerOfTwoBelow(n);
  return m <= k
    ? [...subproof(m, hashes, lo, lo + k, b), mth(hashes, lo + k, hi)]
    : [...subproof(m - k, hashes, lo + k, hi, false), mth(hashes, lo, lo + k)];
}
const proof = (m, hashes) => subproof(m, hashes, 0, hashes.length, true);

// RFC 9162 §2.1.3.2 inclusion verification
function verifyInclusion({ leafHash, leafIndex, treeSize, auditPath, rootHash }) {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash;
  for (const p of auditPath) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = hashChildren(p, r);
      if (fn % 2 === 0) {
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
  return sn === 0 && r.equals(rootHash);
}

// RFC 9162 §2.1.4.2 consistency verification
function verifyConsistency({ first, second, firstRoot, secondRoot, consistencyPath }) {
  if (!Number.isInteger(first) || first <= 0 || first >= second) return false;
  if (consistencyPath.length === 0) return false;
  const isPow2 = (n) => (n & (n - 1)) === 0;
  const p = isPow2(first) ? [firstRoot, ...consistencyPath] : [...consistencyPath];
  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = p[0];
  let sr = p[0];
  for (const c of p.slice(1)) {
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
  return sn === 0 && fr.equals(firstRoot) && sr.equals(secondRoot);
}

function verifySignature(publicKeyMultibase, message, signatureB64url) {
  try {
    const raw = Buffer.from(publicKeyMultibase.replace(/^z/, ""), "base64url");
    if (raw.length !== 32) return false;
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    return edVerify(
      null,
      Buffer.from(message, "utf8"),
      { key: spki, format: "der", type: "spki" },
      Buffer.from(signatureB64url, "base64url"),
    );
  } catch {
    return false;
  }
}

// DESIGN.md §7 relying-party STH checks: shape → key pin → signature → logId → treeSize floor
function verifySth(sth, opts = {}) {
  const p = sth?.payload;
  if (
    !p ||
    p.schema !== "jiaozi.tlog-sth.v1" ||
    typeof p.logId !== "string" ||
    !Number.isInteger(p.treeSize) ||
    p.treeSize < 0 ||
    typeof p.timestamp !== "string" ||
    typeof p.rootHash !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(p.rootHash) ||
    typeof sth.signature !== "string" ||
    typeof sth.publicKeyMultibase !== "string"
  ) {
    return { valid: false, reason: "bad_shape" };
  }
  if (opts.trustedKeys && !opts.trustedKeys.includes(sth.publicKeyMultibase)) {
    return { valid: false, reason: "untrusted_key" };
  }
  if (!verifySignature(sth.publicKeyMultibase, canonicalJson(p), sth.signature)) {
    return { valid: false, reason: "bad_signature" };
  }
  if (opts.expectedLogId && p.logId !== opts.expectedLogId) {
    return { valid: false, reason: "log_id_mismatch" };
  }
  if (opts.minTreeSize !== undefined && p.treeSize < opts.minTreeSize) {
    return { valid: false, reason: "tree_size_regression" };
  }
  return { valid: true };
}

// ---- run the vectors ----

const data = JSON.parse(readFileSync(join(here, "test-vectors.json"), "utf8"));

console.log("== entries: schema, canonical round-trip, leaf hashes (DESIGN.md §4–§5) ==");
const ENTRY_FIELDS = ["certId", "contentHash", "eventType", "schema", "timestamp"];
const EVENT_TYPES = ["cert_issued", "cert_suspended", "cert_reinstated", "cert_revoked"];
const leafHashes = [];
for (const e of data.entries) {
  const name = `entry-${e.leafIndex}`;
  const fieldsOk =
    JSON.stringify(Object.keys(e.entry).sort()) === JSON.stringify(ENTRY_FIELDS) &&
    e.entry.schema === "jiaozi.tlog.v1" &&
    EVENT_TYPES.includes(e.entry.eventType) &&
    /^(JIAOZI|JP)-\d{4}-\d{6,9}$/.test(e.entry.certId) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(e.entry.timestamp) &&
    /^sha256:[0-9a-f]{64}$/.test(e.entry.contentHash);
  if (fieldsOk) ok(`${name} schema`);
  else bad(`${name} schema`);
  if (canonicalJson(e.entry) === e.canonicalEntry) ok(`${name} canonical`);
  else bad(`${name} canonical`, "canonicalJson mismatch");
  const lh = hashLeaf(Buffer.from(e.canonicalEntry, "utf8"));
  if (hex(lh) === e.leafHash) ok(`${name} leaf hash`);
  else bad(`${name} leaf hash`, `recomputed ${hex(lh)}`);
  leafHashes.push(lh);
}

console.log("== tree heads: independent MTH recomputation (RFC 9162 §2.1.1) ==");
for (const th of data.treeHeads) {
  const root = hex(mth(leafHashes.slice(0, th.treeSize)));
  if (root === th.rootHash) ok(`root @ treeSize ${th.treeSize}`);
  else bad(`root @ treeSize ${th.treeSize}`, `recomputed ${root}`);
}

console.log("== inclusion proofs (RFC 9162 §2.1.3) ==");
for (const v of data.vectors.inclusion) {
  const parsed = {
    leafHash: unhex(v.leafHash),
    leafIndex: v.leafIndex,
    treeSize: v.treeSize,
    auditPath: v.auditPath.map(unhex),
    rootHash: unhex(v.rootHash),
  };
  const valid = verifyInclusion(parsed);
  if (valid === v.expect.valid) ok(v.name);
  else bad(v.name, `verifier said ${valid}, expected ${v.expect.valid}`);
  if (v.expect.valid) {
    // regenerate the audit path independently and compare byte-for-byte
    const regen = path(v.leafIndex, leafHashes.slice(0, v.treeSize)).map(hex);
    if (JSON.stringify(regen) === JSON.stringify(v.auditPath)) ok(`${v.name} (path regen)`);
    else bad(`${v.name} (path regen)`, "PATH() disagrees with vector auditPath");
  }
}

console.log("== consistency proofs (RFC 9162 §2.1.4) ==");
for (const v of data.vectors.consistency) {
  const parsed = {
    first: v.first,
    second: v.second,
    firstRoot: unhex(v.firstRoot),
    secondRoot: unhex(v.secondRoot),
    consistencyPath: v.consistencyPath.map(unhex),
  };
  const valid = verifyConsistency(parsed);
  if (valid === v.expect.valid) ok(v.name);
  else bad(v.name, `verifier said ${valid}, expected ${v.expect.valid}`);
  if (v.expect.valid) {
    const regen = proof(v.first, leafHashes.slice(0, v.second)).map(hex);
    if (JSON.stringify(regen) === JSON.stringify(v.consistencyPath)) ok(`${v.name} (proof regen)`);
    else bad(`${v.name} (proof regen)`, "PROOF() disagrees with vector consistencyPath");
  }
}

console.log("== signed tree heads (DESIGN.md §7) ==");
for (const v of data.vectors.sth) {
  const res = verifySth(v.sth, v.verifyOptions ?? {});
  const matched =
    res.valid === v.expect.valid && (v.expect.valid || res.reason === v.expect.reason);
  if (matched) ok(v.name);
  else bad(v.name, `got ${JSON.stringify(res)}, expected ${JSON.stringify(v.expect)}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exitCode = 1;
