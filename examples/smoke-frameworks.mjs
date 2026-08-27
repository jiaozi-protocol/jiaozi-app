#!/usr/bin/env node
/**
 * Framework examples smoke — no LangChain/CrewAI install required.
 * Exercises the same bootstrap + verify path the examples wrap.
 */
import { createHash, randomUUID } from "node:crypto";
import { Gdid } from "../packages/gdid-sdk-js/src/index.ts";

const gdid = new Gdid({
  baseUrl: process.env.JIAOZI_BASE_URL ?? "http://127.0.0.1:3000",
  coreUrl: process.env.JIAOZI_CORE_URL ?? "http://127.0.0.1:3001",
  apiKey: process.env.JIAOZI_API_KEY ?? "dev-key-change-me",
});

function summary(name, owner) {
  return {
    schema: "jiaozi.attest.v1",
    agentName: name,
    softwareGeneHash: "sha256:" + createHash("sha256").update(name + owner).digest("hex"),
    checks: { maliciousApi: "pass", secretLeak: "pass" },
    score: 95,
    trustLevel: "software",
    ownerPubkey: owner,
    timestamp: new Date().toISOString(),
    clientNonce: randomUUID().replaceAll("-", ""),
  };
}

async function bootstrap(name) {
  const owner = "zFw" + createHash("sha256").update(name).digest("hex").slice(0, 32);
  await gdid.register({ name, ownerPubkey: owner, capabilities: ["framework-smoke"] });
  return gdid.attest(summary(name, owner));
}

let failed = 0;
function ok(label, cond) {
  if (!cond) {
    console.error("FAIL", label);
    failed += 1;
  } else console.log("OK  ", label);
}

console.log("=== framework examples smoke ===");
const a = await bootstrap("FwLangChainAgent");
const b = await bootstrap("FwCrewAgent");
ok("langchain-style attest", !!a.certId);
ok("crewai-style attest", !!b.certId);
const v = await gdid.verify(b.certId);
ok("cross-verify", v.ok === true && v.revoked === false);
console.log({ langchainCert: a.certId, crewCert: b.certId });

if (failed) {
  console.error(`framework smoke: ${failed} failed`);
  process.exit(1);
}
console.log("framework smoke: OK");
console.log("Next: python examples/langchain-py/run.py | python examples/crewai/run.py");
