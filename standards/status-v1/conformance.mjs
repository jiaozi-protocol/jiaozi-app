#!/usr/bin/env node
// jiaozi.status.v1 conformance tester — the referee.
// Zero dependencies; independent verifier implementation (does NOT import gdid-core,
// so a bug in the reference implementation cannot hide itself).
//
// Usage:
//   node conformance.mjs                          # offline: run test-vectors.json
//   node conformance.mjs <baseUrl> [certId]       # live: test an issuer deployment
//   e.g. node conformance.mjs https://www.jiaozi.io JP-2026-000016
import { verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
let pass = 0;
let fail = 0;
let warn = 0;

function ok(name, detail = "") {
  pass++;
  console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ""}`);
}
function bad(name, detail = "") {
  fail++;
  console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`);
}
function note(name, detail = "") {
  warn++;
  console.log(`  WARN  ${name}${detail ? ` — ${detail}` : ""}`);
}

// ---- independent implementation of the spec ----

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
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

const STATUSES = new Set(["active", "suspended", "revoked", "unknown"]);

function checkShape(cred) {
  if (!cred || typeof cred !== "object") return "not an object";
  if (typeof cred.signature !== "string") return "signature missing";
  if (typeof cred.publicKeyMultibase !== "string") return "publicKeyMultibase missing";
  const p = cred.payload;
  if (!p || typeof p !== "object") return "payload missing";
  if (p.schema !== "jiaozi.status.v1") return `schema=${p.schema}`;
  if (typeof p.certId !== "string") return "certId missing";
  if (!STATUSES.has(p.status)) return `status=${p.status}`;
  if (typeof p.serial !== "number") return "serial missing";
  if (typeof p.signedAt !== "string" || typeof p.expiresAt !== "string") return "timestamps missing";
  if (typeof p.issuer !== "string") return "issuer missing";
  return null;
}

// spec §7 order: shape → key pin → signature → expiry → issuer pin → serial floor
function verifyCredential(cred, opts = {}) {
  const shapeErr = checkShape(cred);
  if (shapeErr) return { valid: false, reason: "bad_shape" };
  if (opts.trustedKeys && !opts.trustedKeys.includes(cred.publicKeyMultibase)) {
    return { valid: false, reason: "untrusted_key" };
  }
  if (!verifySignature(cred.publicKeyMultibase, canonicalJson(cred.payload), cred.signature)) {
    return { valid: false, reason: "bad_signature" };
  }
  const now = opts.now ?? new Date();
  if (now.getTime() > new Date(cred.payload.expiresAt).getTime()) {
    return { valid: false, reason: "expired" };
  }
  if (opts.expectedIssuer && cred.payload.issuer !== opts.expectedIssuer) {
    return { valid: false, reason: "issuer_mismatch" };
  }
  if (opts.minSerial !== undefined && cred.payload.serial < opts.minSerial) {
    return { valid: false, reason: "serial_regression" };
  }
  return { valid: true };
}

// ---- offline mode: test vectors ----

function runVectors() {
  console.log("== offline: test-vectors.json ==");
  const data = JSON.parse(readFileSync(join(here, "test-vectors.json"), "utf8"));
  for (const v of data.vectors) {
    const opts = { now: new Date(v.verifyAt) };
    if (v.verifyOptions?.trustedKeys) opts.trustedKeys = v.verifyOptions.trustedKeys;
    if (v.verifyOptions?.minSerialDelta !== undefined) {
      opts.minSerial = v.credential.payload.serial + v.verifyOptions.minSerialDelta;
    }
    const res = verifyCredential(v.credential, opts);
    const matched =
      res.valid === v.expect.valid && (v.expect.valid || res.reason === v.expect.reason);
    if (matched) ok(v.name);
    else bad(v.name, `got ${JSON.stringify(res)}, expected ${JSON.stringify(v.expect)}`);
    // canonical serialization must round-trip byte-identically
    if (canonicalJson(v.credential.payload) === v.canonicalPayload) ok(`${v.name} (canonical)`);
    else bad(`${v.name} (canonical)`, "canonicalJson mismatch");
  }
}

// ---- live mode: probe a deployment ----

async function getJson(url) {
  const res = await fetch(url, { headers: { "User-Agent": "jiaozi-conformance/1.0" } });
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* keep null */
  }
  return { status: res.status, body };
}

async function runLive(base, certId) {
  console.log(`== live: ${base} (cert ${certId}) ==`);

  // 1. published signing key (spec §6 SHOULD)
  let pinnedKey = null;
  const keyRes = await getJson(`${base}/api/status-key`);
  if (keyRes.status === 200 && typeof keyRes.body?.publicKeyMultibase === "string") {
    pinnedKey = keyRes.body.publicKeyMultibase;
    ok("status-key endpoint", pinnedKey);
    if (keyRes.body.ephemeral === true)
      note("signing key is ephemeral", "relying parties cannot pin across restarts");
  } else {
    note("status-key endpoint", `HTTP ${keyRes.status} — key pinning unavailable (SHOULD)`);
  }

  // 2. known cert: shape + signature + freshness
  const r1 = await getJson(`${base}/api/status/${certId}`);
  if (r1.status !== 200) {
    bad("known cert HTTP 200", `got ${r1.status} — is ${certId} issued on this deployment?`);
    return;
  }
  ok("known cert HTTP 200");
  const shapeErr = checkShape(r1.body);
  if (shapeErr) {
    bad("credential shape", shapeErr);
    return;
  }
  ok("credential shape");
  const v1 = verifyCredential(r1.body, pinnedKey ? { trustedKeys: [pinnedKey] } : {});
  if (v1.valid) ok("signature + expiry" + (pinnedKey ? " + key pin" : ""));
  else bad("signature + expiry", v1.reason);

  const p = r1.body.payload;
  const ttl = (new Date(p.expiresAt).getTime() - new Date(p.signedAt).getTime()) / 1000;
  if (ttl > 0 && ttl <= 3600) ok("TTL sane", `${ttl}s`);
  else bad("TTL sane", `${ttl}s (must be >0, should be <=3600)`);
  const skew = Math.abs(Date.now() - new Date(p.signedAt).getTime()) / 1000;
  if (skew <= 60) ok("signedAt near now", `${skew.toFixed(1)}s skew`);
  else note("signedAt near now", `${skew.toFixed(1)}s skew — cached or clock drift?`);
  if (p.certId === certId.toUpperCase().replace(/^JJ-/, "JP-")) ok("certId normalized");
  else note("certId normalized", `payload says ${p.certId}`);

  // 3. serial monotonicity across two fetches (spec §8)
  await new Promise((r) => setTimeout(r, 1500));
  const r2 = await getJson(`${base}/api/status/${certId}`);
  if (r2.status === 200 && !checkShape(r2.body)) {
    if (r2.body.payload.serial >= p.serial) ok("serial monotonic", `${p.serial} -> ${r2.body.payload.serial}`);
    else bad("serial monotonic", `${p.serial} -> ${r2.body.payload.serial} (regression)`);
  } else {
    note("serial monotonic", "second fetch failed, skipped");
  }

  // 4. unknown cert: 404 but still signed (spec §10)
  const rU = await getJson(`${base}/api/status/JP-2099-999999`);
  if (rU.status === 404) ok("unknown cert HTTP 404");
  else note("unknown cert HTTP 404", `got ${rU.status}`);
  if (!checkShape(rU.body) && rU.body.payload.status === "unknown") {
    const vU = verifyCredential(rU.body);
    if (vU.valid) ok("unknown is still signed", "no unsigned decision gap");
    else bad("unknown is still signed", vU.reason);
  } else {
    bad("unknown is still signed", "body is not a signed unknown credential");
  }
}

// ---- main ----

const [, , base, certArg] = process.argv;
runVectors();
if (base) {
  await runLive(base.replace(/\/+$/, ""), certArg ?? "JP-2026-000016");
}
console.log(`\n${pass} passed, ${fail} failed, ${warn} warnings`);
if (fail > 0) process.exitCode = 1;
