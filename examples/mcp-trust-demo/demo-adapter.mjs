/**
 * Scripted walkthrough against the adapter-edition server (MCP tools/call).
 * Start `node --import tsx examples/mcp-trust-demo/server-with-adapter.mjs`
 * first, then run:  node examples/mcp-trust-demo/demo-adapter.mjs
 */

const BASE = process.env.DEMO_BASE ?? "http://127.0.0.1:8788";
const META_STATUS = "jiaozi.io/status";
const META_BOUNDARY = "jiaozi.io/boundary";

const pack = await (await fetch(`${BASE}/demo/credentials`)).json();
const { credentials, narrowBoundary } = pack;

const scenarios = [
  { name: "read, no credential", tool: "read", expect: "ok" },
  { name: "write, no credential", tool: "write", expect: "no_credential" },
  { name: "write, bronze (software)", tool: "write", cred: "bronze", expect: "insufficient_level" },
  { name: "write, silver (cloud_attest)", tool: "write", cred: "silver", expect: "ok" },
  { name: "admin, silver (cloud_attest)", tool: "admin", cred: "silver", expect: "insufficient_level" },
  { name: "admin, gold (tee)", tool: "admin", cred: "gold", expect: "ok" },
  { name: "admin, gold + read/write boundary", tool: "admin", cred: "gold", boundary: true, expect: "behavior_out_of_boundary" },
  { name: "write, expired silver", tool: "write", cred: "expired", expect: "expired" },
  { name: "admin, revoked gold", tool: "admin", cred: "revoked", expect: "revoked" },
  { name: "unknown tool (fail-closed)", tool: "format_disk", cred: "gold", expectCode: -32602 },
  { name: "write, silver via x-jiaozi-status header lane", tool: "write", credHeader: "silver", expect: "ok" },
];

let id = 0;
let failures = 0;
for (const s of scenarios) {
  const _meta = {};
  if (s.cred) _meta[META_STATUS] = credentials[s.cred].credential;
  if (s.boundary) _meta[META_BOUNDARY] = narrowBoundary;
  const headers = { "content-type": "application/json" };
  if (s.credHeader) headers["x-jiaozi-status"] = credentials[s.credHeader].header;

  const res = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: ++id,
      method: "tools/call",
      params: { name: s.tool, arguments: {}, ...(Object.keys(_meta).length ? { _meta } : {}) },
    }),
  });
  const body = await res.json();

  let ok;
  let outcome;
  if (s.expectCode !== undefined) {
    ok = body.error?.code === s.expectCode;
    outcome = `error code ${body.error?.code}`;
  } else if (s.expect === "ok") {
    ok = !body.error && body.result?.content?.[0]?.type === "text";
    outcome = ok ? JSON.parse(body.result.content[0].text).tier : `error ${body.error?.data?.reasonCode}`;
  } else {
    ok = body.error?.data?.reasonCode === s.expect;
    outcome = body.error?.data?.reasonCode ?? "unexpected success";
  }

  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${s.name} → ${outcome}`);
  if (body.error?.message) console.log(`        message: ${body.error.message}`);
}

console.log(failures === 0 ? "\nall scenarios behaved as expected" : `\n${failures} scenario(s) off`);
process.exitCode = failures === 0 ? 0 : 1;
