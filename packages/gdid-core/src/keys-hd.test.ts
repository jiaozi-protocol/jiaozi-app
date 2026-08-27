import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createOwnerRoot,
  deriveAgentFromOwner,
  generateEd25519Keypair,
  rotateDidDocumentKeys,
  runAttestationChain,
  signWithPkcs8,
  verifyWithMultibase,
} from "./index.js";

describe("keys + hd + attest plugins", () => {
  it("generates and verifies ed25519 signatures", () => {
    const kp = generateEd25519Keypair();
    const sig = signWithPkcs8(kp.privateKeyPkcs8Base64, "hello");
    assert.equal(verifyWithMultibase(kp.publicKeyMultibase, "hello", sig), true);
  });

  it("rotates did document keys", () => {
    const doc = {
      id: "did:web:example:agents:a",
      controller: "did:web:example:agents:a",
      verificationMethod: [
        {
          id: "did:web:example:agents:a#key-1",
          type: "Ed25519VerificationKey2020",
          controller: "did:web:example:agents:a",
          publicKeyMultibase: "zOld",
        },
      ],
      authentication: ["did:web:example:agents:a#key-1"],
      assertionMethod: ["did:web:example:agents:a#key-1"],
    };
    const next = rotateDidDocumentKeys({ document: doc, newPublicKeyMultibase: "zNew" });
    assert.equal(next.authentication[0].endsWith("#key-2"), true);
    assert.equal(next.verificationMethod[0].revoked, true);
  });

  it("derives owner → domain → agent", () => {
    const owner = createOwnerRoot();
    const { domain, agent } = deriveAgentFromOwner(owner, "finance", "bot-1");
    assert.equal(domain.role, "domain");
    assert.equal(agent.role, "agent");
    assert.ok(agent.path.includes("finance"));
    const again = deriveAgentFromOwner(owner, "finance", "bot-1");
    assert.equal(again.agent.publicKeyMultibase, agent.publicKeyMultibase);
  });

  it("attestation degrades to software by default", async () => {
    const ev = await runAttestationChain({ softwareGeneHash: "sha256:" + "ab".repeat(32) });
    assert.equal(ev.trustLevel, "software");
    assert.equal(ev.degraded, true);
  });
});
