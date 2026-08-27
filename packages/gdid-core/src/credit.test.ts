import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CREDIT_SCHEMA,
  buildMerkleProof,
  chainLink,
  hashCreditEvent,
  hashLocalCreditDetail,
  merkleRoot,
  verifyMerkleProof,
  type CreditEventV1,
} from "./credit.js";

describe("credit merkle", () => {
  it("hashes events stably", () => {
    const ev: CreditEventV1 = {
      schema: CREDIT_SCHEMA,
      subject: "JP-2026-000001",
      type: "attest_issued",
      summaryHash: hashLocalCreditDetail({ note: "local only" }),
      severity: "info",
      scoreDelta: 1,
      timestamp: "2026-07-14T00:00:00.000Z",
      clientNonce: "abc",
      tags: ["b", "a"],
    };
    const h1 = hashCreditEvent(ev);
    const h2 = hashCreditEvent({ ...ev, tags: ["a", "b"] });
    assert.equal(h1, h2);
    assert.match(h1, /^sha256:[0-9a-f]{64}$/);
  });

  it("builds and verifies inclusion proof", () => {
    const leaves = ["sha256:" + "11".repeat(32), "sha256:" + "22".repeat(32), "sha256:" + "33".repeat(32)];
    const root = merkleRoot(leaves);
    for (let i = 0; i < leaves.length; i++) {
      const proof = buildMerkleProof(leaves, i);
      assert.equal(proof.root, root);
      assert.equal(verifyMerkleProof(proof), true);
    }
    const bad = buildMerkleProof(leaves, 0);
    bad.root = "sha256:" + "ff".repeat(32);
    assert.equal(verifyMerkleProof(bad), false);
  });

  it("chains anchors", () => {
    const r1 = merkleRoot(["sha256:" + "aa".repeat(32)]);
    const r2 = merkleRoot(["sha256:" + "bb".repeat(32)]);
    const link = chainLink(r1, r2);
    assert.match(link, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(link, r2);
  });
});
