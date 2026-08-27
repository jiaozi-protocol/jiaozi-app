/**
 * attest.v1 delegation 扩展容器(结构预留位,R3 签字 2026-08-25)的行为锁定:
 * ① 带 delegation 对象的摘要通过形状校验并可规范化序列化(进签名域);
 * ② 不带该字段的存量摘要行为与之前完全一致;
 * ③ delegation 为非对象(字符串/数字/数组/null)时被拒绝。
 * 语义对齐 standards/delegation-v1/DESIGN.md §4.2 / §6.3 / §6.4。
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ATTEST_SCHEMA,
  canonicalJson,
  isAttestSummaryV1,
  type AttestSummaryV1,
} from "./index.js";

function baseSummary(): AttestSummaryV1 {
  return {
    schema: ATTEST_SCHEMA,
    agentName: "DemoAgent",
    softwareGeneHash: "sha256:" + "ab".repeat(32),
    checks: { maliciousApi: "pass", secretLeak: "pass" },
    score: 100,
    trustLevel: "software",
    ownerPubkey: "z6MkDemoOwnerKey",
    timestamp: "2026-08-25T00:00:00.000Z",
    clientNonce: "deadbeefdeadbeef",
  };
}

describe("attest.v1 delegation reserved container", () => {
  it("absent delegation stays valid (legacy credentials unchanged)", () => {
    const summary = baseSummary();
    assert.equal(isAttestSummaryV1(summary), true);
    assert.ok(!canonicalJson(summary).includes("delegation"));
  });

  it("accepts an empty delegation object", () => {
    const summary: AttestSummaryV1 = { ...baseSummary(), delegation: {} };
    assert.equal(isAttestSummaryV1(summary), true);
  });

  it("accepts delegation as an opaque object without inspecting subfields", () => {
    // 子字段草案(delegation-v1 DESIGN §4.2):delegator / grantedCapabilities /
    // caveats / expiresAt —— v1 不做运行时校验,任意内部结构均放行
    const summary: AttestSummaryV1 = {
      ...baseSummary(),
      delegation: {
        delegator: "JIAOZI-2026-000123",
        grantedCapabilities: ["procure", "pay"],
        caveats: [{ type: "maxAmountPerTx", currency: "CNY", value: 10000 }],
        expiresAt: "2026-09-01T00:00:00.000Z",
        anythingElse: { nested: true },
      },
    };
    assert.equal(isAttestSummaryV1(summary), true);
  });

  it("delegation enters the canonical JSON signing domain when present", () => {
    const without = baseSummary();
    const withDelegation: AttestSummaryV1 = {
      ...baseSummary(),
      delegation: { delegator: "JIAOZI-2026-000123" },
    };
    assert.notEqual(canonicalJson(withDelegation), canonicalJson(without));
    assert.ok(canonicalJson(withDelegation).includes('"delegation"'));
    // 序列化确定性:同一对象两次 canonicalJson 逐字节一致
    assert.equal(canonicalJson(withDelegation), canonicalJson(withDelegation));
  });

  it("rejects non-object delegation (string / number / array / null)", () => {
    for (const bad of ["delegated", 42, ["JIAOZI-2026-000123"], null]) {
      const candidate = { ...baseSummary(), delegation: bad };
      assert.equal(
        isAttestSummaryV1(candidate),
        false,
        `delegation=${JSON.stringify(bad)} must be rejected`,
      );
    }
  });
});
