import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { multiStandardViews, toDidKeyView, toW3cDidView } from "./index.js";

const doc = {
  id: "did:web:www.jiaozi.io:agents:jj-2026-000001",
  controller: "did:web:www.jiaozi.io:agents:jj-2026-000001",
  verificationMethod: [
    {
      id: "did:web:www.jiaozi.io:agents:jj-2026-000001#key-1",
      type: "Ed25519VerificationKey2020",
      controller: "did:web:www.jiaozi.io:agents:jj-2026-000001",
      publicKeyMultibase: "zDemoOwnerKey",
    },
  ],
  authentication: ["did:web:www.jiaozi.io:agents:jj-2026-000001#key-1"],
  assertionMethod: ["did:web:www.jiaozi.io:agents:jj-2026-000001#key-1"],
};

describe("adapters", () => {
  it("w3c view passthrough", () => {
    const v = toW3cDidView(doc);
    assert.equal(v.standardId, "w3c-did-core");
    assert.equal((v.view as { id: string }).id, doc.id);
  });

  it("did:key view", () => {
    const v = toDidKeyView(doc);
    assert.equal(v.standardId, "did-key");
    assert.equal((v.view as { id: string }).id, "did:key:zDemoOwnerKey");
  });

  it("multi views", () => {
    assert.equal(multiStandardViews(doc).length, 2);
  });
});
