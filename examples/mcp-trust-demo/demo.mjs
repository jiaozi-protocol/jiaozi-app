/**
 * Scripted walkthrough of the three trust tiers against a running demo server.
 * Start `node examples/mcp-trust-demo/server.mjs` first, then run:
 *   node examples/mcp-trust-demo/demo.mjs
 */

const BASE = process.env.DEMO_BASE ?? "http://127.0.0.1:8787";

const pack = await (await fetch(`${BASE}/demo/credentials`)).json();
const { credentials, narrowBoundaryHeader } = pack;

const scenarios = [
  { name: "read, no credential", method: "GET", tool: "read", expect: 200 },
  { name: "write, no credential", tool: "write", expect: 401 },
  { name: "write, bronze (software)", tool: "write", cred: "bronze", expect: 403 },
  { name: "write, silver (cloud_attest)", tool: "write", cred: "silver", expect: 200 },
  { name: "admin, silver (cloud_attest)", tool: "admin", cred: "silver", expect: 403 },
  { name: "admin, gold (tee)", tool: "admin", cred: "gold", expect: 200 },
  { name: "admin, gold + read/write boundary", tool: "admin", cred: "gold", boundary: true, expect: 403 },
  { name: "write, expired silver", tool: "write", cred: "expired", expect: 403 },
  { name: "admin, revoked gold", tool: "admin", cred: "revoked", expect: 403 },
];

let failures = 0;
for (const s of scenarios) {
  const headers = {};
  if (s.cred) headers["x-jiaozi-status"] = credentials[s.cred].header;
  if (s.boundary) headers["x-jiaozi-boundary"] = narrowBoundaryHeader;
  const res = await fetch(`${BASE}/tools/${s.tool}`, { method: s.method ?? "POST", headers });
  const body = await res.json();
  const ok = res.status === s.expect;
  if (!ok) failures += 1;
  const outcome = body.ok ? `ok (${body.tier})` : `${body.error}`;
  console.log(`${ok ? "PASS" : "FAIL"}  [${res.status}] ${s.name} → ${outcome}`);
  if (body.reason) console.log(`        reason: ${body.reason}`);
}

console.log(failures === 0 ? "\nall scenarios behaved as expected" : `\n${failures} scenario(s) off`);
// natural exit (process.exit here trips a libuv teardown assertion on Windows
// while undici keep-alive sockets are still open)
process.exitCode = failures === 0 ? 0 : 1;
