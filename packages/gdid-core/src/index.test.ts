import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  composeOidIdentityCode,
  createSoftwareDidDocument,
  formatCertId,
  normalizeCertId,
  toStandardEd25519Multibase,
  ATTEST_SCHEMA,
} from "./index.js";

describe("toStandardEd25519Multibase", () => {
  // did:key 规范测试向量:全零 32 字节公钥 → z6Mk 开头的 base58btc(0xed01 前缀)
  const raw = Buffer.alloc(32, 7);
  const house = "z" + raw.toString("base64url");

  it("converts house z+base64url to spec multibase (z6Mk…)", () => {
    const std = toStandardEd25519Multibase(house);
    assert.match(std, /^z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    // 往返:base58 解码后应还原 0xed01 + 原始 32 字节
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let n = 0n;
    for (const c of std.slice(1)) n = n * 58n + BigInt(alphabet.indexOf(c));
    const bytes = [];
    while (n > 0n) {
      bytes.unshift(Number(n & 0xffn));
      n >>= 8n;
    }
    const decoded = Buffer.from(bytes);
    assert.equal(decoded[0], 0xed);
    assert.equal(decoded[1], 0x01);
    assert.deepEqual(decoded.subarray(2), raw);
  });

  it("is idempotent on already-standard keys", () => {
    const std = toStandardEd25519Multibase(house);
    assert.equal(toStandardEd25519Multibase(std), std);
  });

  it("leaves unparseable input untouched", () => {
    assert.equal(toStandardEd25519Multibase("zDemoOwnerKey"), "zDemoOwnerKey");
  });
});

describe("createSoftwareDidDocument conformance", () => {
  it("includes @context and spec-encoded verification key", () => {
    const doc = createSoftwareDidDocument({
      did: "did:web:www.jiaozi.io:agents:jp-2026-000001",
      controller: "did:web:www.jiaozi.io:agents:jp-2026-000001",
      certId: "JP-2026-000001",
      ownerPubkeyMultibase: "z" + Buffer.alloc(32, 7).toString("base64url"),
    });
    assert.ok(doc["@context"]?.includes("https://www.w3.org/ns/did/v1"));
    assert.match(doc.verificationMethod[0].publicKeyMultibase ?? "", /^z6Mk/);
  });
});

describe("formatCertId", () => {
  it("pads sequence to 6 digits", () => {
    assert.equal(formatCertId(2026, 1), "JIAOZI-2026-000001");
  });

  it("grows naturally beyond 6 digits up to 200M", () => {
    assert.equal(formatCertId(2026, 1_000_000), "JIAOZI-2026-1000000");
    assert.equal(formatCertId(2026, 200_000_000), "JIAOZI-2026-200000000");
  });

  it("rejects out of range", () => {
    assert.throws(() => formatCertId(2026, 0));
    assert.throws(() => formatCertId(2026, 200_000_001));
  });
});

describe("normalizeCertId", () => {
  it("maps legacy JJ prefix to JP and uppercases", () => {
    assert.equal(normalizeCertId("jj-2026-000016"), "JP-2026-000016");
    assert.equal(normalizeCertId("JJ-2026-000001"), "JP-2026-000001");
  });

  it("keeps JIAOZI ids uppercase and never rewrites legacy JP", () => {
    assert.equal(normalizeCertId("jiaozi-2026-000021"), "JIAOZI-2026-000021");
    assert.equal(normalizeCertId(" JIAOZI-2026-000021 "), "JIAOZI-2026-000021");
  });

  it("uppercases JP ids; leaves non-cert inputs untouched", () => {
    assert.equal(normalizeCertId(" jp-2026-000016 "), "JP-2026-000016");
    assert.equal(normalizeCertId("did:web:www.jiaozi.io:agents:jp-2026-000016"), "did:web:www.jiaozi.io:agents:jp-2026-000016");
  });
});

describe("composeOidIdentityCode", () => {
  it("assembles the GB/Z 185.2 six-segment structure", () => {
    assert.equal(
      composeOidIdentityCode({
        arcPrefix: "1.2.156.3088.1.77",
        requesterCode: 42,
        ontologySerial: 16,
      }),
      "1.2.156.3088.1.77.42.16.1",
    );
  });

  it("accepts explicit instance serial and alphanumeric segments", () => {
    assert.equal(
      composeOidIdentityCode({
        arcPrefix: "1.2.156.3088.1.ZZ9",
        requesterCode: "A7",
        ontologySerial: 3,
        instanceSerial: 12,
      }),
      "1.2.156.3088.1.ZZ9.A7.3.12",
    );
  });

  it("rejects malformed segments", () => {
    assert.throws(() =>
      composeOidIdentityCode({ arcPrefix: "not an oid", requesterCode: 1, ontologySerial: 1 }),
    );
    assert.throws(() =>
      composeOidIdentityCode({
        arcPrefix: "1.2.156.3088.1.77",
        requesterCode: "has space",
        ontologySerial: 1,
      }),
    );
  });
});

describe("schema constant", () => {
  it("matches contract", () => {
    assert.equal(ATTEST_SCHEMA, "jiaozi.attest.v1");
  });
});
