/**
 * Same three trust tiers as server.mjs, rebuilt on the @jiaozi/adapters MCP
 * adapter: the manual gate() plumbing collapses into one declarative policy
 * table + plain handlers, and the endpoint speaks real MCP `tools/call`
 * JSON-RPC. Credentials arrive via params._meta["jiaozi.io/status"] or the
 * x-jiaozi-status header — both lanes work.
 *
 * Run from repo root (adapters exports TS source, so load tsx):
 *   npm run build -w @jiaozi-protocol/gdid-core -w @jiaozi-protocol/sdk   # once
 *   node --import tsx examples/mcp-trust-demo/server-with-adapter.mjs
 */

import { createServer } from "node:http";
import {
  buildStatusPayload,
  generateEd25519Keypair,
  signStatusPayload,
} from "@jiaozi-protocol/gdid-core";
import { wrapToolHandler, TRUST_STATUS_META_KEY } from "@jiaozi/adapters";

const PORT = Number(process.env.PORT ?? 8788);
const ISSUER = "mcp-trust-demo";
const TTL_SECONDS = 600;

// ---- demo issuer + credentials (identical to server.mjs) --------------------

const issuerKeys = generateEd25519Keypair();

function mint({ certId, trustLevel, status = "active", now }) {
  const payload = buildStatusPayload({
    certId,
    did: `did:web:demo.local:agents:${certId}`,
    status,
    trustLevel,
    issuer: ISSUER,
    ttlSeconds: TTL_SECONDS,
    now,
  });
  const credential = signStatusPayload(
    payload,
    issuerKeys.privateKeyPkcs8Base64,
    issuerKeys.publicKeyMultibase,
  );
  return { credential, header: Buffer.from(JSON.stringify(credential)).toString("base64url") };
}

const demo = {
  bronze: mint({ certId: "JIAOZI-2026-100001", trustLevel: "software" }),
  silver: mint({ certId: "JIAOZI-2026-100002", trustLevel: "cloud_attest" }),
  gold: mint({ certId: "JIAOZI-2026-100003", trustLevel: "tee" }),
  expired: mint({
    certId: "JIAOZI-2026-100004",
    trustLevel: "cloud_attest",
    now: new Date(Date.now() - 3600_000),
  }),
  revoked: mint({ certId: "JIAOZI-2026-100005", trustLevel: "tee", status: "revoked" }),
};

const narrowBoundary = { permissions: ["read", "write"] };

// ---- the entire trust wiring: one policy table + plain handlers -------------

const caller = (trust) =>
  trust.certId ? { certId: trust.certId, trustLevel: trust.trustLevel } : "anonymous";

const handleToolCall = wrapToolHandler(
  {
    tools: {
      read: { public: true },
      write: { minLevel: "cloud_attest", behaviors: ["write"] },
      admin: { minLevel: "tee", behaviors: ["admin"] },
    },
    trust: { verify: { trustedKeys: [issuerKeys.publicKeyMultibase], expectedIssuer: ISSUER } },
  },
  {
    read: (_args, { trust }) => ({
      ok: true, tool: "read", tier: "public",
      data: { motd: "public knowledge base — anyone can read this" },
      caller: caller(trust),
    }),
    write: (_args, { trust }) => ({
      ok: true, tool: "write", tier: "silver+", result: "document saved", caller: caller(trust),
    }),
    admin: (_args, { trust }) => ({
      ok: true, tool: "admin", tier: "gold", result: "server settings updated", caller: caller(trust),
    }),
  },
);

// ---- http transport ---------------------------------------------------------

function json(res, code, body) {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body, null, 2));
}

const server = createServer((req, res) => {
  const path = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`).pathname;

  if (path === "/mcp" && req.method === "POST") {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      let request;
      try {
        request = JSON.parse(raw);
      } catch {
        json(res, 200, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
        return;
      }
      // JSON-RPC responses ride HTTP 200; denials live in the error member
      json(res, 200, await handleToolCall(request, { headers: req.headers }));
    });
    return;
  }

  if (path === "/demo/credentials") {
    json(res, 200, {
      note: `demo credentials, TTL 10 min; put the credential JSON at params._meta["${TRUST_STATUS_META_KEY}"] of a tools/call request, or send the base64url header value as x-jiaozi-status`,
      issuerPublicKeyMultibase: issuerKeys.publicKeyMultibase,
      credentials: Object.fromEntries(
        Object.entries(demo).map(([k, v]) => [k, { credential: v.credential, header: v.header }]),
      ),
      narrowBoundary,
      example: {
        jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: "write", arguments: {}, _meta: { [TRUST_STATUS_META_KEY]: "<credential JSON>" } },
      },
    });
    return;
  }

  json(res, path === "/" ? 200 : 404, {
    name: "mcp-trust-demo (adapter edition)",
    endpoint: "POST /mcp — MCP tools/call (JSON-RPC 2.0)",
    tools: {
      read: "public — no credential",
      write: "silver (cloud_attest) or above",
      admin: "gold (tee/tpm) + 'admin' within declared boundary",
    },
    demo: "GET /demo/credentials",
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mcp-trust-demo (adapter edition) listening on http://127.0.0.1:${PORT}`);
  console.log(`demo credentials: http://127.0.0.1:${PORT}/demo/credentials`);
});
