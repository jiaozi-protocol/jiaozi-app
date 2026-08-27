import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildStatusPayload,
  generateEd25519Keypair,
  signStatusPayload,
  type CertLiveStatus,
  type StatusCredentialV1,
  type TrustLevel,
} from "@jiaozi-protocol/gdid-core";
import {
  defineToolPolicy,
  gateToolCall,
  MCP_TRUST_DENIED_CODE,
  MCP_UNKNOWN_TOOL_CODE,
  presentationFromMcpRequest,
  toolCallError,
  TRUST_BOUNDARY_META_KEY,
  TRUST_STATUS_META_KEY,
  wrapToolHandler,
  type McpPolicyOptions,
  type McpToolCallRequest,
} from "./mcp.js";

// ---- offline test-credential mint (same technique as require-trust.test.ts) --

const issuer = generateEd25519Keypair();

function mintCredential(input: {
  trustLevel?: TrustLevel | null;
  status?: CertLiveStatus;
  ttlSeconds?: number;
  now?: Date;
  certId?: string;
}): StatusCredentialV1 {
  const payload = buildStatusPayload({
    certId: input.certId ?? "JIAOZI-2026-000042",
    did: `did:web:core.jiaozi.io:agents:${input.certId ?? "JIAOZI-2026-000042"}`,
    status: input.status ?? "active",
    trustLevel: input.trustLevel === undefined ? "software" : input.trustLevel,
    issuer: "test-issuer",
    ttlSeconds: input.ttlSeconds ?? 300,
    now: input.now,
  });
  return signStatusPayload(payload, issuer.privateKeyPkcs8Base64, issuer.publicKeyMultibase);
}

const bronze = mintCredential({ trustLevel: "software" });
const silver = mintCredential({ trustLevel: "cloud_attest" });
const gold = mintCredential({ trustLevel: "tee" });

/** Three-tier policy, mirroring examples/mcp-trust-demo. */
const policyOptions: McpPolicyOptions = {
  tools: {
    read: { public: true },
    write: { minLevel: "cloud_attest", behaviors: ["write"] },
    admin: { minLevel: "tee", behaviors: ["admin"] },
  },
};
const policy = defineToolPolicy(policyOptions);

function callRequest(
  toolName: string,
  meta?: Record<string, unknown>,
  id: string | number = 1,
): McpToolCallRequest {
  return {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name: toolName, arguments: {}, ...(meta ? { _meta: meta } : {}) },
  };
}

describe("gateToolCall — three tiers (policy table × requireTrust)", () => {
  it("public tool allows anonymous access (no credential)", () => {
    const d = gateToolCall(policy, { toolName: "read" });
    assert.equal(d.allowed, true);
    if (d.allowed) {
      assert.equal(d.tier, "public");
      assert.equal(d.trustLevel, null);
    }
  });

  it("public tool identifies a caller presenting a valid credential", () => {
    const d = gateToolCall(policy, { toolName: "read", presentation: { statusCredential: gold } });
    assert.equal(d.allowed, true);
    if (d.allowed) {
      assert.equal(d.tier, "public");
      assert.equal(d.trustLevel, "tee");
      assert.equal(d.certId, "JIAOZI-2026-000042");
    }
  });

  it("gated tool denies with no credential (no_credential)", () => {
    const d = gateToolCall(policy, { toolName: "write" });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "no_credential");
      assert.match(d.reason, /未出示/);
      assert.match(d.reason, /No status credential/);
    }
  });

  it("bronze denied on the silver tool (insufficient_level)", () => {
    const d = gateToolCall(policy, { toolName: "write", presentation: { statusCredential: bronze } });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "insufficient_level");
  });

  it("silver passes the silver tool but not the gold tool", () => {
    const w = gateToolCall(policy, { toolName: "write", presentation: { statusCredential: silver } });
    assert.equal(w.allowed, true);
    if (w.allowed) {
      assert.equal(w.tier, "gated");
      assert.equal(w.trustLevel, "cloud_attest");
    }
    const a = gateToolCall(policy, { toolName: "admin", presentation: { statusCredential: silver } });
    assert.equal(a.allowed, false);
    if (!a.allowed) assert.equal(a.reasonCode, "insufficient_level");
  });

  it("gold passes everything (read / write / admin)", () => {
    for (const toolName of ["read", "write", "admin"]) {
      const d = gateToolCall(policy, { toolName, presentation: { statusCredential: gold } });
      assert.equal(d.allowed, true, `gold should pass ${toolName}`);
    }
  });

  it("gold with a narrow declared boundary is denied admin (behavior_out_of_boundary)", () => {
    const d = gateToolCall(policy, {
      toolName: "admin",
      presentation: { statusCredential: gold, behaviorBoundary: { permissions: ["read", "write"] } },
    });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "behavior_out_of_boundary");
      assert.match(d.reason, /越界:admin/);
    }
  });

  it("expired credential denied (expired)", () => {
    const expired = mintCredential({
      trustLevel: "cloud_attest",
      ttlSeconds: 60,
      now: new Date(Date.now() - 3600_000),
    });
    const d = gateToolCall(policy, { toolName: "write", presentation: { statusCredential: expired } });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "expired");
  });

  it("revoked credential denied even at gold level (revoked)", () => {
    const revoked = mintCredential({ trustLevel: "revoked", status: "revoked" });
    const d = gateToolCall(policy, { toolName: "admin", presentation: { statusCredential: revoked } });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "revoked");
  });

  it("suspended credential denied (suspended)", () => {
    const suspended = mintCredential({ trustLevel: "tee", status: "suspended" });
    const d = gateToolCall(policy, { toolName: "write", presentation: { statusCredential: suspended } });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "suspended");
  });

  it("tampered credential denied (invalid_credential / bad_signature)", () => {
    const tampered = { ...bronze, payload: { ...bronze.payload, trustLevel: "tpm" as const } };
    const d = gateToolCall(policy, { toolName: "admin", presentation: { statusCredential: tampered } });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "invalid_credential");
      assert.match(d.reason, /bad_signature/);
    }
  });
});

describe("gateToolCall — policy table edges", () => {
  it("tool absent from table with no default → unknown_tool (fail-closed)", () => {
    const d = gateToolCall(policy, { toolName: "delete_everything", presentation: { statusCredential: gold } });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "unknown_tool");
  });

  it("tool absent from table falls through to the default rule when declared", () => {
    const withDefault = defineToolPolicy({
      tools: { read: { public: true } },
      default: { minLevel: "cloud_attest" },
    });
    const anon = gateToolCall(withDefault, { toolName: "anything" });
    assert.equal(anon.allowed, false);
    if (!anon.allowed) assert.equal(anon.reasonCode, "no_credential");
    const ok = gateToolCall(withDefault, { toolName: "anything", presentation: { statusCredential: silver } });
    assert.equal(ok.allowed, true);
  });

  it("shared trust wiring reaches every compiled gate (trustedKeys pinning)", () => {
    const pinned = defineToolPolicy({
      tools: { write: { minLevel: "cloud_attest" } },
      trust: { verify: { trustedKeys: ["z-not-this-key"] } },
    });
    const d = gateToolCall(pinned, { toolName: "write", presentation: { statusCredential: silver } });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.match(d.reason, /untrusted_key/);
  });

  it("fail-closed at compile time: pinned policy without issuerKeys throws", () => {
    assert.throws(
      () => defineToolPolicy({ tools: { write: {} }, trust: { policy: "pinned" } }),
      /issuerKeys/,
    );
  });
});

describe("presentationFromMcpRequest — _meta and header lanes are equivalent", () => {
  const boundary = { permissions: ["read", "write"] };

  it("reads the credential JSON object straight from params._meta", () => {
    const p = presentationFromMcpRequest(
      callRequest("write", { [TRUST_STATUS_META_KEY]: silver, [TRUST_BOUNDARY_META_KEY]: boundary }),
    );
    assert.deepEqual(p.statusCredential, silver);
    assert.deepEqual(p.behaviorBoundary, boundary);
  });

  it("accepts base64url and raw-JSON strings in _meta (same parser as headers)", () => {
    const b64 = Buffer.from(JSON.stringify(silver)).toString("base64url");
    const fromB64 = presentationFromMcpRequest(callRequest("write", { [TRUST_STATUS_META_KEY]: b64 }));
    assert.deepEqual(fromB64.statusCredential, silver);
    const fromRaw = presentationFromMcpRequest(
      callRequest("write", { [TRUST_STATUS_META_KEY]: JSON.stringify(silver) }),
    );
    assert.deepEqual(fromRaw.statusCredential, silver);
  });

  it("falls back to x-jiaozi-status / x-jiaozi-boundary headers on HTTP transports", () => {
    const p = presentationFromMcpRequest(callRequest("write"), {
      "x-jiaozi-status": Buffer.from(JSON.stringify(silver)).toString("base64url"),
      "x-jiaozi-boundary": JSON.stringify(boundary),
    });
    assert.deepEqual(p.statusCredential, silver);
    assert.deepEqual(p.behaviorBoundary, boundary);
  });

  it("_meta lane and header lane produce the same gate decision", () => {
    const viaMeta = gateToolCall(policy, {
      toolName: "write",
      presentation: presentationFromMcpRequest(callRequest("write", { [TRUST_STATUS_META_KEY]: silver })),
    });
    const viaHeaders = gateToolCall(policy, {
      toolName: "write",
      presentation: presentationFromMcpRequest(callRequest("write"), {
        "x-jiaozi-status": JSON.stringify(silver),
      }),
    });
    assert.deepEqual(viaMeta, viaHeaders);
    assert.equal(viaMeta.allowed, true);
  });

  it("_meta wins over headers when both are present (field-wise)", () => {
    const p = presentationFromMcpRequest(callRequest("write", { [TRUST_STATUS_META_KEY]: gold }), {
      "x-jiaozi-status": JSON.stringify(bronze),
    });
    assert.deepEqual(p.statusCredential, gold);
  });
});

describe("wrapToolHandler — gated tools/call dispatcher", () => {
  const handle = wrapToolHandler(policyOptions, {
    read: () => ({ content: [{ type: "text", text: "public knowledge" }] }),
    write: (_args, ctx) => `saved by ${ctx.trust.certId} (${ctx.trust.trustLevel})`,
    admin: () => {
      throw new Error("disk on fire");
    },
  });

  it("allows and returns the handler result (id echoed, content normalized)", async () => {
    const res = await handle(callRequest("write", { [TRUST_STATUS_META_KEY]: silver }, 7));
    assert.equal(res.id, 7);
    assert.equal(res.error, undefined);
    const content = (res.result as { content: Array<{ type: string; text: string }> }).content;
    assert.equal(content[0].type, "text");
    assert.match(content[0].text, /saved by JIAOZI-2026-000042 \(cloud_attest\)/);
  });

  it("denies with a spec-shaped JSON-RPC error: code, bilingual message, reasonCode in data", async () => {
    const res = await handle(callRequest("write", undefined, "req-9"));
    assert.equal(res.jsonrpc, "2.0");
    assert.equal(res.id, "req-9");
    assert.equal(res.result, undefined);
    assert.ok(res.error);
    assert.equal(res.error.code, MCP_TRUST_DENIED_CODE);
    assert.match(res.error.message, /未出示/);
    assert.match(res.error.message, /No status credential/);
    assert.equal((res.error.data as { reasonCode: string }).reasonCode, "no_credential");
    assert.equal((res.error.data as { tool: string }).tool, "write");
  });

  it("denial data carries trustLevel and certId for level failures", async () => {
    const res = await handle(callRequest("admin", { [TRUST_STATUS_META_KEY]: silver }));
    assert.ok(res.error);
    assert.equal(res.error.code, MCP_TRUST_DENIED_CODE);
    const data = res.error.data as { reasonCode: string; trustLevel: string; certId: string };
    assert.equal(data.reasonCode, "insufficient_level");
    assert.equal(data.trustLevel, "cloud_attest");
    assert.equal(data.certId, "JIAOZI-2026-000042");
  });

  it("unknown tool → -32602 per MCP spec convention", async () => {
    const res = await handle(callRequest("format_disk", { [TRUST_STATUS_META_KEY]: gold }));
    assert.ok(res.error);
    assert.equal(res.error.code, MCP_UNKNOWN_TOOL_CODE);
    assert.match(res.error.message, /Unknown tool: format_disk/);
  });

  it("missing tool name → -32602 invalid params", async () => {
    const res = await handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: {} });
    assert.ok(res.error);
    assert.equal(res.error.code, MCP_UNKNOWN_TOOL_CODE);
  });

  it("handler exception → tool-execution error (isError: true result), not a protocol error", async () => {
    const res = await handle(callRequest("admin", { [TRUST_STATUS_META_KEY]: gold }));
    assert.equal(res.error, undefined);
    const result = res.result as { isError: boolean; content: Array<{ text: string }> };
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /disk on fire/);
  });

  it("accepts headers from an HTTP transport as the credential lane", async () => {
    const res = await handle(callRequest("write"), {
      headers: { "x-jiaozi-status": Buffer.from(JSON.stringify(silver)).toString("base64url") },
    });
    assert.equal(res.error, undefined);
  });
});

describe("toolCallError — standalone translation", () => {
  it("maps a trust denial onto MCP_TRUST_DENIED_CODE with null id fallback", () => {
    const denied = gateToolCall(policy, { toolName: "write" });
    assert.equal(denied.allowed, false);
    if (!denied.allowed) {
      const err = toolCallError(denied, undefined);
      assert.equal(err.id, null);
      assert.equal(err.error?.code, MCP_TRUST_DENIED_CODE);
    }
  });
});
