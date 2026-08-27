import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildStatusPayload,
  generateEd25519Keypair,
  signStatusPayload,
  toStandardEd25519Multibase,
  type CertLiveStatus,
  type StatusCredentialV1,
  type TrustLevel,
} from "@jiaozi-protocol/gdid-core";
import {
  DEFAULT_STATUS_SOURCE,
  fetchStatusCredential,
  presentationFromHeaders,
  requireTrust,
  requireTrustExpress,
  trustDenyHttpStatus,
  type TrustDecision,
} from "./require-trust.js";

const issuer = generateEd25519Keypair();

function mintCredential(input: {
  trustLevel?: TrustLevel | null;
  status?: CertLiveStatus;
  ttlSeconds?: number;
  now?: Date;
}): StatusCredentialV1 {
  const payload = buildStatusPayload({
    certId: "JIAOZI-2026-000042",
    did: "did:web:core.jiaozi.io:agents:JIAOZI-2026-000042",
    status: input.status ?? "active",
    trustLevel: input.trustLevel === undefined ? "software" : input.trustLevel,
    issuer: "test-issuer",
    ttlSeconds: input.ttlSeconds ?? 300,
    now: input.now,
  });
  return signStatusPayload(payload, issuer.privateKeyPkcs8Base64, issuer.publicKeyMultibase);
}

describe("requireTrust — pure checker", () => {
  it("allows a valid active credential at default minLevel", () => {
    const check = requireTrust();
    const d = check({ statusCredential: mintCredential({}) });
    assert.equal(d.allowed, true);
    if (d.allowed) {
      assert.equal(d.trustLevel, "software");
      assert.equal(d.certId, "JIAOZI-2026-000042");
    }
  });

  it("denies when no credential is presented (no_credential)", () => {
    const check = requireTrust();
    for (const d of [check(), check(null), check({})]) {
      assert.equal(d.allowed, false);
      if (!d.allowed) {
        assert.equal(d.reasonCode, "no_credential");
        assert.match(d.reason, /未出示/);
        assert.match(d.reason, /No status credential/);
      }
    }
  });

  it("denies an expired credential (expired)", () => {
    const past = new Date(Date.now() - 3600_000);
    const check = requireTrust();
    const d = check({ statusCredential: mintCredential({ ttlSeconds: 60, now: past }) });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "expired");
      assert.match(d.reason, /过期/);
    }
  });

  it("denies a revoked credential even if fresh (revoked)", () => {
    const check = requireTrust();
    const d = check({ statusCredential: mintCredential({ status: "revoked", trustLevel: "revoked" }) });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "revoked");
      assert.match(d.reason, /吊销/);
      assert.equal(d.certId, "JIAOZI-2026-000042");
    }
  });

  it("denies a suspended credential (suspended)", () => {
    const check = requireTrust();
    const d = check({ statusCredential: mintCredential({ status: "suspended" }) });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "suspended");
  });

  it("fails closed on unknown live status (invalid_credential)", () => {
    const check = requireTrust();
    const d = check({ statusCredential: mintCredential({ status: "unknown" }) });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "invalid_credential");
  });

  it("denies a tampered credential (invalid_credential)", () => {
    const cred = mintCredential({});
    const tampered = {
      ...cred,
      payload: { ...cred.payload, trustLevel: "tpm" as const },
    };
    const check = requireTrust();
    const d = check({ statusCredential: tampered });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "invalid_credential");
      assert.match(d.reason, /bad_signature/);
    }
  });

  it("denies below minLevel (insufficient_level), bronze < silver < gold", () => {
    const silverGate = requireTrust({ minLevel: "cloud_attest" });
    const bronze = silverGate({ statusCredential: mintCredential({ trustLevel: "software" }) });
    assert.equal(bronze.allowed, false);
    if (!bronze.allowed) {
      assert.equal(bronze.reasonCode, "insufficient_level");
      assert.match(bronze.reason, /等级不足/);
    }

    const silver = silverGate({ statusCredential: mintCredential({ trustLevel: "cloud_attest" }) });
    assert.equal(silver.allowed, true);

    const goldGate = requireTrust({ minLevel: "tee" });
    assert.equal(goldGate({ statusCredential: mintCredential({ trustLevel: "cloud_attest" }) }).allowed, false);
    // tee and tpm are both gold — either satisfies a gold gate
    assert.equal(goldGate({ statusCredential: mintCredential({ trustLevel: "tpm" }) }).allowed, true);
    assert.equal(goldGate({ statusCredential: mintCredential({ trustLevel: "tee" }) }).allowed, true);
  });

  it("treats null trustLevel as below any gate (insufficient_level)", () => {
    const check = requireTrust();
    const d = check({ statusCredential: mintCredential({ trustLevel: null }) });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.equal(d.reasonCode, "insufficient_level");
  });

  it("denies behaviours outside a declared boundary (behavior_out_of_boundary)", () => {
    const writeGate = requireTrust({ behaviors: ["write"] });
    const d = writeGate({
      statusCredential: mintCredential({}),
      behaviorBoundary: { permissions: ["read"] },
    });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "behavior_out_of_boundary");
      assert.match(d.reason, /越界:write/);
    }
  });

  it("allows behaviours inside the boundary, or when no boundary declared", () => {
    const writeGate = requireTrust({ behaviors: ["write"] });
    const inside = writeGate({
      statusCredential: mintCredential({}),
      behaviorBoundary: { permissions: ["read", "write"] },
    });
    assert.equal(inside.allowed, true);
    const undeclared = writeGate({ statusCredential: mintCredential({}) });
    assert.equal(undeclared.allowed, true);
  });

  it("honours verify passthrough (trustedKeys pinning)", () => {
    const check = requireTrust({ verify: { trustedKeys: ["z-not-this-key"] } });
    const d = check({ statusCredential: mintCredential({}) });
    assert.equal(d.allowed, false);
    if (!d.allowed) assert.match(d.reason, /untrusted_key/);
  });
});

describe("requireTrust — 分级验证策略 online/pinned/offline", () => {
  const pinnedStandard = toStandardEd25519Multibase(issuer.publicKeyMultibase);

  it("defaults to online and marks freshness verified", () => {
    const d = requireTrust()({ statusCredential: mintCredential({}) });
    assert.equal(d.allowed, true);
    if (d.allowed) assert.equal(d.freshness, "verified");
  });

  it("never downgrades unless offline is chosen: expired denied under online and pinned", () => {
    const past = new Date(Date.now() - 3600_000);
    const expired = mintCredential({ ttlSeconds: 60, now: past });
    for (const check of [
      requireTrust(),
      requireTrust({ policy: "online" }),
      requireTrust({ policy: "pinned", issuerKeys: [pinnedStandard] }),
    ]) {
      const d = check({ statusCredential: expired });
      assert.equal(d.allowed, false);
      if (!d.allowed) assert.equal(d.reasonCode, "expired");
    }
  });

  it("pinned verifies locally against a pinned issuer key (z6Mk or legacy form)", () => {
    for (const key of [pinnedStandard, issuer.publicKeyMultibase]) {
      const check = requireTrust({ policy: "pinned", issuerKeys: [key] });
      const d = check({ statusCredential: mintCredential({}) });
      assert.equal(d.allowed, true);
      if (d.allowed) assert.equal(d.freshness, "verified");
    }
  });

  it("pinned rejects a credential whose embedded key matches no pin", () => {
    const stranger = generateEd25519Keypair();
    const check = requireTrust({
      policy: "pinned",
      issuerKeys: [toStandardEd25519Multibase(stranger.publicKeyMultibase)],
    });
    const d = check({ statusCredential: mintCredential({}) });
    assert.equal(d.allowed, false);
    if (!d.allowed) {
      assert.equal(d.reasonCode, "invalid_credential");
      assert.match(d.reason, /pinned_key_mismatch/);
    }
  });

  it("pinned and offline refuse to build without issuerKeys (fail-closed)", () => {
    assert.throws(() => requireTrust({ policy: "pinned" }), /issuerKeys/);
    assert.throws(() => requireTrust({ policy: "offline", issuerKeys: [] }), /issuerKeys/);
  });

  it("offline verifies signature locally and marks freshness unverified", () => {
    const check = requireTrust({ policy: "offline", issuerKeys: [pinnedStandard] });
    const past = new Date(Date.now() - 3600_000);
    // 过期凭证在 offline 下仍可通过,但结果显式标注新鲜度未验证
    for (const cred of [mintCredential({}), mintCredential({ ttlSeconds: 60, now: past })]) {
      const d = check({ statusCredential: cred });
      assert.equal(d.allowed, true);
      if (d.allowed) assert.equal(d.freshness, "unverified");
    }
  });

  it("offline still denies revoked, key-mismatched and tampered credentials", () => {
    const check = requireTrust({ policy: "offline", issuerKeys: [pinnedStandard] });

    const revoked = check({
      statusCredential: mintCredential({ status: "revoked", trustLevel: "revoked" }),
    });
    assert.equal(revoked.allowed, false);
    if (!revoked.allowed) assert.equal(revoked.reasonCode, "revoked");

    const stranger = generateEd25519Keypair();
    const strangerCred = signStatusPayload(
      mintCredential({}).payload,
      stranger.privateKeyPkcs8Base64,
      stranger.publicKeyMultibase,
    );
    const mismatch = check({ statusCredential: strangerCred });
    assert.equal(mismatch.allowed, false);
    if (!mismatch.allowed) assert.match(mismatch.reason, /pinned_key_mismatch/);

    const cred = mintCredential({});
    const tampered = { ...cred, payload: { ...cred.payload, trustLevel: "tpm" as const } };
    const bad = check({ statusCredential: tampered });
    assert.equal(bad.allowed, false);
    if (!bad.allowed) assert.match(bad.reason, /bad_signature/);
  });
});

describe("fetchStatusCredential", () => {
  it("GETs the credential from the default or a configured status source", async () => {
    const cred = mintCredential({});
    const calls: string[] = [];
    const fakeFetch = (async (url: unknown) => {
      calls.push(String(url));
      return { json: async () => cred } as Response;
    }) as typeof fetch;

    const fromDefault = await fetchStatusCredential("JIAOZI-2026-000042", { fetch: fakeFetch });
    assert.deepEqual(fromDefault, cred);
    assert.equal(calls[0], `${DEFAULT_STATUS_SOURCE}/api/status/JIAOZI-2026-000042`);

    await fetchStatusCredential("JIAOZI-2026-000042", {
      statusSource: "https://mirror.jiaozi.tech/",
      fetch: fakeFetch,
    });
    assert.equal(calls[1], "https://mirror.jiaozi.tech/api/status/JIAOZI-2026-000042");
  });
});

describe("presentationFromHeaders", () => {
  it("parses raw JSON and base64 headers", () => {
    const cred = mintCredential({});
    const boundary = { permissions: ["read"] };
    const fromRaw = presentationFromHeaders({
      "x-jiaozi-status": JSON.stringify(cred),
      "x-jiaozi-boundary": JSON.stringify(boundary),
    });
    assert.deepEqual(fromRaw.statusCredential, cred);
    assert.deepEqual(fromRaw.behaviorBoundary, boundary);

    const fromB64 = presentationFromHeaders({
      "x-jiaozi-status": Buffer.from(JSON.stringify(cred)).toString("base64url"),
    });
    assert.deepEqual(fromB64.statusCredential, cred);
  });

  it("yields no credential for absent or garbled headers", () => {
    assert.equal(presentationFromHeaders({}).statusCredential, undefined);
    assert.equal(
      presentationFromHeaders({ "x-jiaozi-status": "not json at all" }).statusCredential,
      undefined,
    );
  });
});

describe("requireTrustExpress", () => {
  function run(middleware: ReturnType<typeof requireTrustExpress>, headers: Record<string, string>) {
    let statusCode = 0;
    let body: unknown;
    let nextCalled = false;
    const req = { headers } as { headers: Record<string, string>; jiaoziTrust?: TrustDecision };
    middleware(
      req,
      {
        status(code: number) {
          statusCode = code;
          return {
            json(b: unknown) {
              body = b;
              return b;
            },
          };
        },
      },
      () => {
        nextCalled = true;
      },
    );
    return { statusCode, body, nextCalled, req };
  }

  it("calls next() and attaches the decision on allow", () => {
    const mw = requireTrustExpress({ minLevel: "software" });
    const { nextCalled, req } = run(mw, {
      "x-jiaozi-status": JSON.stringify(mintCredential({})),
    });
    assert.equal(nextCalled, true);
    assert.equal(req.jiaoziTrust?.allowed, true);
  });

  it("responds 401 with reason when no credential", () => {
    const mw = requireTrustExpress();
    const { statusCode, body, nextCalled } = run(mw, {});
    assert.equal(nextCalled, false);
    assert.equal(statusCode, 401);
    assert.equal((body as { error: string }).error, "no_credential");
  });

  it("responds 403 with reason on insufficient level", () => {
    const mw = requireTrustExpress({ minLevel: "tee" });
    const { statusCode, body } = run(mw, {
      "x-jiaozi-status": JSON.stringify(mintCredential({ trustLevel: "software" })),
    });
    assert.equal(statusCode, 403);
    assert.equal((body as { error: string }).error, "insufficient_level");
  });
});

describe("trustDenyHttpStatus", () => {
  it("maps no_credential → 401, everything else → 403", () => {
    assert.equal(trustDenyHttpStatus("no_credential"), 401);
    for (const code of [
      "invalid_credential",
      "expired",
      "revoked",
      "suspended",
      "insufficient_level",
      "behavior_out_of_boundary",
    ] as const) {
      assert.equal(trustDenyHttpStatus(code), 403);
    }
  });
});
