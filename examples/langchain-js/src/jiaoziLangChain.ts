/**
 * LangChain-oriented GDID helpers (works without @langchain/* installed).
 * When LangChain is present, wrap `verifyPeerToolSpec` with DynamicStructuredTool.
 */
import { createHash, randomUUID } from "node:crypto";
import { Gdid, type AttestSummaryV1 } from "../../../packages/gdid-sdk-js/src/index.ts";

export type BootstrapBundle = {
  agentName: string;
  ownerPubkey: string;
  agentId?: string;
  registrationDid?: string;
  certId: string;
  did: string;
  trustLevel?: string;
};

function env(name: string, fallback: string): string {
  return (process.env[name] ?? fallback).trim();
}

export function createClient(): Gdid {
  return new Gdid({
    baseUrl: env("JIAOZI_BASE_URL", "http://127.0.0.1:3000"),
    coreUrl: env("JIAOZI_CORE_URL", "http://127.0.0.1:3001"),
    apiKey: env("JIAOZI_API_KEY", "dev-key-change-me"),
  });
}

export function demoOwnerPubkey(label: string): string {
  return `zDemo${createHash("sha256").update(`jiaozi-${label}`).digest("hex").slice(0, 40)}`;
}

export function buildSummary(agentName: string, ownerPubkey: string): AttestSummaryV1 {
  const gene =
    "sha256:" + createHash("sha256").update(`${agentName}:${ownerPubkey}`).digest("hex");
  return {
    schema: "jiaozi.attest.v1",
    agentName,
    softwareGeneHash: gene,
    checks: { maliciousApi: "pass", secretLeak: "pass" },
    score: 95,
    trustLevel: "software",
    ownerPubkey,
    timestamp: new Date().toISOString(),
    clientNonce: randomUUID().replaceAll("-", ""),
  };
}

/** Startup: register + attest so the LangChain agent carries a cert. */
export async function bootstrapAgent(
  agentName: string,
  capabilities: string[] = ["langchain-demo"],
): Promise<BootstrapBundle> {
  const gdid = createClient();
  const ownerPubkey = demoOwnerPubkey(agentName);
  const reg = await gdid.register({ name: agentName, ownerPubkey, capabilities });
  const issued = await gdid.attest(buildSummary(agentName, ownerPubkey));
  return {
    agentName,
    ownerPubkey,
    agentId: reg.agentId,
    registrationDid: reg.did,
    certId: issued.certId,
    did: issued.did,
    trustLevel: issued.trustLevel,
  };
}

const TRUST_ORDER = ["software", "cloud_attest", "tee", "tpm"] as const;

/** Call before trusting another agent / tool target. */
export async function requireVerified(
  didOrCert: string,
  minTrust: (typeof TRUST_ORDER)[number] = "software",
) {
  const result = await createClient().verify(didOrCert);
  if (!result.ok) {
    throw new Error(`GDID verify failed: ${result.reason ?? "unknown"}`);
  }
  if (result.revoked || result.trustLevel === "revoked") {
    throw new Error("GDID revoked");
  }
  const trust = (result.trustLevel ?? "software") as (typeof TRUST_ORDER)[number];
  if (TRUST_ORDER.indexOf(trust) < TRUST_ORDER.indexOf(minTrust)) {
    throw new Error(`trustLevel ${trust} < required ${minTrust}`);
  }
  return result;
}

/** LangChain tool schema (JSON) — bind with DynamicStructuredTool / tool(). */
export const verifyPeerToolSpec = {
  name: "jiaozi_verify_peer",
  description:
    "Verify a peer AI Agent identity via Jiaozi GDID (certId or DID). Reject if revoked or missing.",
  schema: {
    type: "object",
    properties: {
      didOrCertId: {
        type: "string",
        description: "Peer credential id JIAOZI-YYYY-###### (legacy JP-… accepted) or did:web:...",
      },
    },
    required: ["didOrCertId"],
  },
};

export async function verifyPeerToolHandler(input: { didOrCertId: string }): Promise<string> {
  const v = await requireVerified(input.didOrCertId);
  return JSON.stringify({
    ok: true,
    certId: v.certId,
    did: v.did,
    trustLevel: v.trustLevel,
  });
}
