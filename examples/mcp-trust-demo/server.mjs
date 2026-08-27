/**
 * MCP-style trust-tier demo server — "凭证的价值 = 持证者的权限差".
 *
 * Three tools, three tiers:
 *   GET/POST /tools/read   — public, no credential needed
 *   POST     /tools/write  — requires silver (cloud_attest) or above
 *   POST     /tools/admin  — requires gold (tee/tpm) + "admin" inside the
 *                            agent's declared behaviour boundary
 *
 * On boot the server plays issuer: it mints demo jiaozi.status.v1 credentials
 * (bronze / silver / gold / expired / revoked) and serves them at
 * GET /demo/credentials together with ready-to-paste curl commands.
 *
 * Run from repo root (build the SDK once first):
 *   npm run build -w @jiaozi-protocol/gdid-core -w @jiaozi-protocol/sdk
 *   node examples/mcp-trust-demo/server.mjs
 */

import { createServer } from "node:http";
import {
  buildStatusPayload,
  generateEd25519Keypair,
  signStatusPayload,
} from "@jiaozi-protocol/gdid-core";
import {
  presentationFromHeaders,
  requireTrust,
  trustDenyHttpStatus,
  TRUST_BOUNDARY_HEADER,
  TRUST_STATUS_HEADER,
} from "@jiaozi-protocol/sdk";

const PORT = Number(process.env.PORT ?? 8787);
const ISSUER = "mcp-trust-demo";
const TTL_SECONDS = 600; // 10 min — enough for a manual curl walkthrough

// ---- demo issuer + credentials --------------------------------------------

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
  return {
    credential,
    header: Buffer.from(JSON.stringify(credential)).toString("base64url"),
  };
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

/** attest.v1 behaviorBoundary the "gold" agent declared: read+write only, no admin */
const narrowBoundary = { permissions: ["read", "write"] };
const narrowBoundaryHeader = Buffer.from(JSON.stringify(narrowBoundary)).toString("base64url");

// ---- trust gates ------------------------------------------------------------

const verify = { trustedKeys: [issuerKeys.publicKeyMultibase], expectedIssuer: ISSUER };
const anyValid = requireTrust({ verify });
const writeGate = requireTrust({ minLevel: "cloud_attest", behaviors: ["write"], verify });
const adminGate = requireTrust({ minLevel: "tee", behaviors: ["admin"], verify });

// ---- http plumbing ----------------------------------------------------------

function json(res, code, body) {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body, null, 2));
}

function gate(check, req, res, onAllow) {
  const decision = check(presentationFromHeaders(req.headers));
  if (!decision.allowed) {
    json(res, trustDenyHttpStatus(decision.reasonCode), {
      error: decision.reasonCode,
      reason: decision.reason,
      trustLevel: decision.trustLevel,
      ...(decision.certId ? { certId: decision.certId } : {}),
    });
    return;
  }
  onAllow(decision);
}

const server = createServer((req, res) => {
  const path = new URL(req.url ?? "/", `http://127.0.0.1:${PORT}`).pathname;

  if (path === "/tools/read") {
    // Public tier — works with no credential; echoes trust info if one is shown.
    const presented = presentationFromHeaders(req.headers);
    const decision = presented.statusCredential ? anyValid(presented) : null;
    json(res, 200, {
      ok: true,
      tool: "read",
      tier: "public",
      data: { motd: "public knowledge base — anyone can read this" },
      caller: decision?.allowed
        ? { certId: decision.certId, trustLevel: decision.trustLevel }
        : "anonymous",
    });
    return;
  }

  if (path === "/tools/write" && req.method === "POST") {
    gate(writeGate, req, res, (d) =>
      json(res, 200, {
        ok: true,
        tool: "write",
        tier: "silver+",
        result: "document saved",
        caller: { certId: d.certId, trustLevel: d.trustLevel },
      }),
    );
    return;
  }

  if (path === "/tools/admin" && req.method === "POST") {
    gate(adminGate, req, res, (d) =>
      json(res, 200, {
        ok: true,
        tool: "admin",
        tier: "gold",
        result: "server settings updated",
        caller: { certId: d.certId, trustLevel: d.trustLevel },
      }),
    );
    return;
  }

  if (path === "/demo/credentials") {
    const base = `http://127.0.0.1:${PORT}`;
    const curl = (tool, key, extra = "") =>
      `curl -s -X POST ${base}/tools/${tool} -H "${TRUST_STATUS_HEADER}: ${demo[key].header}"${extra}`;
    json(res, 200, {
      note: "demo credentials, TTL 10 min; header values are base64url(JSON of jiaozi.status.v1)",
      issuerPublicKeyMultibase: issuerKeys.publicKeyMultibase,
      credentials: Object.fromEntries(
        Object.entries(demo).map(([k, v]) => [k, { header: v.header, payload: v.credential.payload }]),
      ),
      narrowBoundaryHeader,
      walkthrough: {
        "1_read_public": `curl -s ${base}/tools/read`,
        "2_write_no_credential_401": `curl -s -X POST ${base}/tools/write`,
        "3_write_bronze_403": curl("write", "bronze"),
        "4_write_silver_200": curl("write", "silver"),
        "5_admin_silver_403": curl("admin", "silver"),
        "6_admin_gold_200": curl("admin", "gold"),
        "7_admin_gold_boundary_403": curl(
          "admin",
          "gold",
          ` -H "${TRUST_BOUNDARY_HEADER}: ${narrowBoundaryHeader}"`,
        ),
        "8_write_expired_403": curl("write", "expired"),
        "9_admin_revoked_403": curl("admin", "revoked"),
      },
    });
    return;
  }

  json(res, path === "/" ? 200 : 404, {
    name: "mcp-trust-demo",
    tools: {
      "GET  /tools/read": "public — no credential",
      "POST /tools/write": "silver (cloud_attest) or above",
      "POST /tools/admin": "gold (tee/tpm) + 'admin' within declared boundary",
    },
    demo: "GET /demo/credentials",
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mcp-trust-demo listening on http://127.0.0.1:${PORT}`);
  console.log(`demo credentials + curl walkthrough: http://127.0.0.1:${PORT}/demo/credentials`);
});
