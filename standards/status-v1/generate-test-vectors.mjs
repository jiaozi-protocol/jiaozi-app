// Deterministic test vectors for jiaozi.status.v1.
// Fixed Ed25519 seed => stable keys and signatures across runs.
// Usage: node standards/status-v1/generate-test-vectors.mjs
import { createPrivateKey, createPublicKey } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildStatusPayload,
  signStatusPayload,
  verifyStatusCredential,
} from "../../packages/gdid-core/dist/status.js";
import { canonicalJson } from "../../packages/gdid-core/dist/credit.js";

const here = dirname(fileURLToPath(import.meta.url));

// Fixed 32-byte seed (test-only key; NEVER use for anything real)
const seed = Buffer.alloc(32, 7);
const pkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  seed,
]);
const privateKeyPkcs8Base64 = pkcs8.toString("base64");
const spki = createPublicKey(
  createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }),
).export({ format: "der", type: "spki" });
const rawPub = spki.subarray(spki.length - 32);
const publicKeyMultibase = "z" + rawPub.toString("base64url");

const ISSUER = "https://www.jiaozi.io";
const T0 = new Date("2026-08-08T00:00:00.000Z");

function vector(name, description, payloadInput, mutate) {
  const payload = buildStatusPayload({ ...payloadInput, issuer: ISSUER, now: T0 });
  const credential = signStatusPayload(payload, privateKeyPkcs8Base64, publicKeyMultibase);
  if (mutate) mutate(credential);
  return { name, description, credential, canonicalPayload: canonicalJson(credential.payload) };
}

const vectors = [];

vectors.push({
  ...vector("valid-active", "Well-formed active credential. MUST verify.", {
    certId: "JP-2026-000001",
    did: "did:web:www.jiaozi.io:agents:jp-2026-000001",
    status: "active",
    trustLevel: "software",
    ttlSeconds: 300,
  }),
  verifyAt: "2026-08-08T00:01:00.000Z",
  expect: { valid: true },
});

vectors.push({
  ...vector("valid-revoked-with-reason", "Revoked credential with reason. MUST verify (the assertion is valid; the cert is not).", {
    certId: "JP-2026-000002",
    did: null,
    status: "revoked",
    trustLevel: null,
    revocationReason: "key-compromise",
    ttlSeconds: 300,
  }),
  verifyAt: "2026-08-08T00:01:00.000Z",
  expect: { valid: true },
});

vectors.push({
  ...vector("expired", "Valid signature but verified after expiresAt. MUST fail: expired.", {
    certId: "JP-2026-000003",
    did: null,
    status: "active",
    trustLevel: "software",
    ttlSeconds: 300,
  }),
  verifyAt: "2026-08-08T00:06:00.000Z",
  expect: { valid: false, reason: "expired" },
});

vectors.push({
  ...vector(
    "tampered-payload",
    "status flipped revoked->active after signing. MUST fail: bad_signature.",
    {
      certId: "JP-2026-000004",
      did: null,
      status: "revoked",
      trustLevel: null,
      ttlSeconds: 300,
    },
    (c) => {
      c.payload.status = "active";
    },
  ),
  verifyAt: "2026-08-08T00:01:00.000Z",
  expect: { valid: false, reason: "bad_signature" },
});

vectors.push({
  ...vector("serial-regression", "Valid credential, but RP already accepted a higher serial. MUST fail: serial_regression (verify with minSerial = serial+1).", {
    certId: "JP-2026-000005",
    did: null,
    status: "active",
    trustLevel: "software",
    ttlSeconds: 300,
  }),
  verifyAt: "2026-08-08T00:01:00.000Z",
  verifyOptions: { minSerialDelta: 1 },
  expect: { valid: false, reason: "serial_regression" },
});

vectors.push({
  ...vector("untrusted-key", "Valid credential, but RP pins a different key. MUST fail: untrusted_key.", {
    certId: "JP-2026-000006",
    did: null,
    status: "active",
    trustLevel: "software",
    ttlSeconds: 300,
  }),
  verifyAt: "2026-08-08T00:01:00.000Z",
  verifyOptions: { trustedKeys: ["zSOME-OTHER-KEY"] },
  expect: { valid: false, reason: "untrusted_key" },
});

// Self-check every vector against the reference implementation before writing.
for (const v of vectors) {
  const opts = { now: new Date(v.verifyAt) };
  if (v.verifyOptions?.trustedKeys) opts.trustedKeys = v.verifyOptions.trustedKeys;
  if (v.verifyOptions?.minSerialDelta !== undefined) {
    opts.minSerial = v.credential.payload.serial + v.verifyOptions.minSerialDelta;
  }
  const res = verifyStatusCredential(v.credential, opts);
  const ok =
    res.valid === v.expect.valid &&
    (v.expect.valid || res.reason === v.expect.reason);
  if (!ok) {
    console.error("SELF-CHECK FAILED:", v.name, "got", res, "expected", v.expect);
    process.exitCode = 1;
  } else {
    console.log("self-check ok:", v.name);
  }
}

const out = {
  schema: "jiaozi.status.v1",
  generated: "deterministic (fixed seed, fixed clock 2026-08-08T00:00:00Z)",
  signingKey: {
    note: "TEST KEY ONLY - seed is 32 bytes of 0x07",
    privateKeyPkcs8Base64,
    publicKeyMultibase,
  },
  vectors,
};
writeFileSync(join(here, "test-vectors.json"), JSON.stringify(out, null, 2) + "\n");
console.log("wrote test-vectors.json with", vectors.length, "vectors");
