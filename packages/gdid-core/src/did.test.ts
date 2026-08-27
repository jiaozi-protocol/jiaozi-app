import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildAgentDid, didWebHttpUrl, isCertId, parseDidWeb } from "./did.js";

describe("did helpers", () => {
  it("builds did:web under core host", () => {
    const did = buildAgentDid("www.jiaozi.io", "JP-2026-000001");
    assert.equal(did, "did:web:www.jiaozi.io:agents:jp-2026-000001");
  });

  it("maps did:web to https did.json path", () => {
    const did = "did:web:www.jiaozi.io:agents:jp-2026-000001";
    assert.equal(didWebHttpUrl(did), "https://www.jiaozi.io/agents/jp-2026-000001/did.json");
  });

  it("parses did:web", () => {
    const parsed = parseDidWeb("did:web:www.jiaozi.io:agents:jp-2026-000001");
    assert.deepEqual(parsed, {
      host: "www.jiaozi.io",
      pathSegments: ["agents", "jp-2026-000001"],
    });
  });

  it("detects cert ids", () => {
    assert.equal(isCertId("JIAOZI-2026-000001"), true);
    assert.equal(isCertId("jiaozi-2026-000001"), true);
    assert.equal(isCertId("JP-2026-000001"), true);
    assert.equal(isCertId("JP-2033-158000000"), true);
    assert.equal(isCertId("JP-2026-1234567890"), false);
    // 历史 JJ 前缀仍作为合法输入接受（归一由 normalizeCertId 负责）
    assert.equal(isCertId("jp-2026-000001"), true);
    assert.equal(isCertId("did:web:x"), false);
  });
});
