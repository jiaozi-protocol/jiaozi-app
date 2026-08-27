import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildStatusPayload,
  generateEd25519Keypair,
  signStatusPayload,
  toStandardEd25519Multibase,
  verifyStatusCredential,
  type StatusCredentialV1,
} from "@jiaozi-protocol/gdid-core";
import { requireTrust } from "./require-trust.js";
import {
  AnchorResolutionError,
  DEFAULT_ANCHORS,
  MIRROR_ANCHOR,
  MIRROR_FETCHED_AT_HEADER,
  MIRROR_SOURCE_HEADER,
  MIRROR_STALE_HEADER,
  PRIMARY_ANCHOR,
  resolveDidDocument,
  resolveStatusCredential,
} from "./multi-anchor.js";

const issuer = generateEd25519Keypair();
const CERT_ID = "JIAOZI-2026-000042";

function mintCredential(input?: { ttlSeconds?: number; now?: Date }): StatusCredentialV1 {
  const payload = buildStatusPayload({
    certId: CERT_ID,
    did: `did:web:core.jiaozi.io:agents:${CERT_ID}`,
    status: "active",
    trustLevel: "software",
    issuer: "test-issuer",
    ttlSeconds: input?.ttlSeconds ?? 300,
    now: input?.now,
  });
  return signStatusPayload(payload, issuer.privateKeyPkcs8Base64, issuer.publicKeyMultibase);
}

/** Route-table fake fetch: per-anchor behaviour + a call log. */
function anchorFetch(
  routes: Record<string, (url: string, init?: RequestInit) => Response | Promise<Response>>,
): { fetchImpl: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = (async (url: unknown, init?: unknown) => {
    const target = String(url);
    calls.push(target);
    const anchor = Object.keys(routes).find((a) => target.startsWith(a));
    if (!anchor) throw new Error(`no route for ${target}`);
    return await routes[anchor]!(target, init as RequestInit | undefined);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function jsonResponse(body: unknown, init?: { status?: number; headers?: Record<string, string> }) {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
}

describe("multi-anchor — 场景①主锚正常", () => {
  it("answers from the primary and never contacts the mirror", async () => {
    const cred = mintCredential();
    const { fetchImpl, calls } = anchorFetch({
      [PRIMARY_ANCHOR]: () => jsonResponse(cred),
      [MIRROR_ANCHOR]: () => {
        throw new Error("mirror must not be contacted when primary is healthy");
      },
    });

    const { credential, provenance } = await resolveStatusCredential(CERT_ID, { fetch: fetchImpl });
    assert.deepEqual(credential, cred);
    assert.equal(calls.length, 1);
    assert.equal(calls[0], `${PRIMARY_ANCHOR}/api/status/${CERT_ID}`);
    assert.equal(provenance.anchor, PRIMARY_ANCHOR);
    assert.equal(provenance.anchorIndex, 0);
    assert.equal(provenance.viaMirror, false);
    assert.equal(provenance.stale, false);
    assert.equal(provenance.degraded, false);
  });

  it("treats 404 as an authoritative answer — no fallback (negative cache contract)", async () => {
    // status 404 is itself a *signed* unknown-status credential (fail-closed downstream)
    const unknownCred = { schema: "jiaozi.status.v1", payload: { status: "unknown" } };
    const { fetchImpl, calls } = anchorFetch({
      [PRIMARY_ANCHOR]: () => jsonResponse(unknownCred, { status: 404 }),
      [MIRROR_ANCHOR]: () => {
        throw new Error("4xx is authoritative; mirror must not be tried");
      },
    });
    const { credential } = await resolveStatusCredential("JIAOZI-2099-999999", { fetch: fetchImpl });
    assert.deepEqual(credential, unknownCred);
    assert.equal(calls.length, 1);
  });
});

describe("multi-anchor — 场景②主锚失败镜像接管", () => {
  const mirrorFreshHeaders = {
    [MIRROR_SOURCE_HEADER]: "sg-origin",
    [MIRROR_STALE_HEADER]: "false",
    "x-jiaozi-mirror-origin": PRIMARY_ANCHOR,
  };

  it("falls back on primary 5xx; the mirrored credential verifies with the same signature path", async () => {
    const cred = mintCredential();
    const { fetchImpl, calls } = anchorFetch({
      [PRIMARY_ANCHOR]: () => jsonResponse({ error: "upstream down" }, { status: 503 }),
      [MIRROR_ANCHOR]: () => jsonResponse(cred, { headers: mirrorFreshHeaders }),
    });

    const { credential, provenance } = await resolveStatusCredential(CERT_ID, { fetch: fetchImpl });
    assert.equal(calls.length, 2);
    assert.equal(provenance.anchor, MIRROR_ANCHOR);
    assert.equal(provenance.anchorIndex, 1);
    assert.equal(provenance.viaMirror, true);
    assert.equal(provenance.mirrorSource, "sg-origin");
    assert.equal(provenance.stale, false);
    assert.equal(provenance.degraded, false);

    // 验签逻辑零改动:镜像取回的字节走同一套 verifyStatusCredential
    const verified = verifyStatusCredential(credential);
    assert.equal(verified.valid, true);
    const decision = requireTrust({
      policy: "pinned",
      issuerKeys: [toStandardEd25519Multibase(issuer.publicKeyMultibase)],
    })({ statusCredential: credential });
    assert.equal(decision.allowed, true);
  });

  it("falls back on primary network error (fetch rejection)", async () => {
    const cred = mintCredential();
    const { fetchImpl } = anchorFetch({
      [PRIMARY_ANCHOR]: () => {
        throw new Error("getaddrinfo ENOTFOUND www.jiaozi.io");
      },
      [MIRROR_ANCHOR]: () => jsonResponse(cred, { headers: mirrorFreshHeaders }),
    });
    const { credential, provenance } = await resolveStatusCredential(CERT_ID, { fetch: fetchImpl });
    assert.deepEqual(credential, cred);
    assert.equal(provenance.anchor, MIRROR_ANCHOR);
  });

  it("falls back on primary timeout (per-anchor abort)", async () => {
    const cred = mintCredential();
    const { fetchImpl } = anchorFetch({
      [PRIMARY_ANCHOR]: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason ?? new Error("aborted")),
          );
        }),
      [MIRROR_ANCHOR]: () => jsonResponse(cred, { headers: mirrorFreshHeaders }),
    });
    const { provenance } = await resolveStatusCredential(CERT_ID, {
      fetch: fetchImpl,
      timeoutMs: 25,
    });
    assert.equal(provenance.anchor, MIRROR_ANCHOR);
  });

  it("a poisoned mirror still fails signature verification (anchor earns no trust)", async () => {
    const cred = mintCredential();
    const poisoned = { ...cred, payload: { ...cred.payload, trustLevel: "tpm" as const } };
    const { fetchImpl } = anchorFetch({
      [PRIMARY_ANCHOR]: () => jsonResponse({}, { status: 502 }),
      [MIRROR_ANCHOR]: () => jsonResponse(poisoned, { headers: mirrorFreshHeaders }),
    });
    const { credential } = await resolveStatusCredential(CERT_ID, { fetch: fetchImpl });
    const verified = verifyStatusCredential(credential);
    assert.equal(verified.valid, false);
    if (!verified.valid) assert.equal(verified.reason, "bad_signature");
  });
});

describe("multi-anchor — 场景③双锚全失败 fail-closed", () => {
  it("throws AnchorResolutionError listing every anchor's failure", async () => {
    const { fetchImpl, calls } = anchorFetch({
      [PRIMARY_ANCHOR]: () => {
        throw new Error("ECONNREFUSED");
      },
      [MIRROR_ANCHOR]: () => jsonResponse({}, { status: 500 }),
    });
    await assert.rejects(
      () => resolveStatusCredential(CERT_ID, { fetch: fetchImpl }),
      (err: unknown) => {
        assert.ok(err instanceof AnchorResolutionError);
        assert.equal(err.failures.length, 2);
        assert.equal(err.failures[0]?.anchor, PRIMARY_ANCHOR);
        assert.match(err.failures[0]?.reason ?? "", /ECONNREFUSED/);
        assert.equal(err.failures[1]?.reason, "http_500");
        assert.match(err.message, /fail-closed/);
        return true;
      },
    );
    assert.equal(calls.length, 2);
  });

  it("an unparseable 200 body counts as anchor failure, not an answer", async () => {
    const badBody = () =>
      new Response("<html>gateway error</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    const { fetchImpl } = anchorFetch({
      [PRIMARY_ANCHOR]: badBody,
      [MIRROR_ANCHOR]: badBody,
    });
    await assert.rejects(
      () => resolveStatusCredential(CERT_ID, { fetch: fetchImpl }),
      (err: unknown) => {
        assert.ok(err instanceof AnchorResolutionError);
        assert.equal(err.failures[0]?.reason, "unparseable_body");
        return true;
      },
    );
  });

  it("refuses an empty anchor list (fail-closed configuration)", async () => {
    await assert.rejects(
      () => resolveStatusCredential(CERT_ID, { anchors: [] }),
      /Empty anchor list/,
    );
  });
});

describe("multi-anchor — 场景④镜像 stale 标注", () => {
  it("surfaces stale-if-error hits as stale+degraded with the copy's fetch time", async () => {
    // 断链场景:镜像供给最后成功副本 —— 一份已过期的真签名凭证
    const past = new Date(Date.now() - 3600_000);
    const staleCred = mintCredential({ ttlSeconds: 60, now: past });
    const fetchedAt = new Date(past.getTime() + 30_000).toISOString();
    const { fetchImpl } = anchorFetch({
      [PRIMARY_ANCHOR]: () => {
        throw new Error("primary domain hijack drill");
      },
      [MIRROR_ANCHOR]: () =>
        jsonResponse(staleCred, {
          headers: {
            [MIRROR_SOURCE_HEADER]: "sg-origin",
            [MIRROR_STALE_HEADER]: "true",
            [MIRROR_FETCHED_AT_HEADER]: fetchedAt,
          },
        }),
    });

    const { credential, provenance } = await resolveStatusCredential(CERT_ID, {
      fetch: fetchImpl,
    });
    assert.equal(provenance.stale, true);
    assert.equal(provenance.degraded, true);
    assert.equal(provenance.mirrorSource, "sg-origin");
    assert.equal(provenance.fetchedAt, fetchedAt);

    // 陈旧不放宽验证:签名仍验得过,但默认/钉扎策略照样按 expired 拒绝
    const pinned = requireTrust({
      policy: "pinned",
      issuerKeys: [toStandardEd25519Multibase(issuer.publicKeyMultibase)],
    })({ statusCredential: credential });
    assert.equal(pinned.allowed, false);
    if (!pinned.allowed) assert.equal(pinned.reasonCode, "expired");

    // 只有显式选 offline 才接受,且结果带 freshness: "unverified"(不静默)
    const offline = requireTrust({
      policy: "offline",
      issuerKeys: [toStandardEd25519Multibase(issuer.publicKeyMultibase)],
    })({ statusCredential: credential });
    assert.equal(offline.allowed, true);
    if (offline.allowed) assert.equal(offline.freshness, "unverified");
  });

  it("marks cn-replica answers degraded; the unsigned replica object fails verification", async () => {
    const replicaBody = { certId: CERT_ID, status: "active", degraded: true };
    const { fetchImpl } = anchorFetch({
      [PRIMARY_ANCHOR]: () => jsonResponse({}, { status: 503 }),
      [MIRROR_ANCHOR]: () =>
        jsonResponse(replicaBody, {
          headers: { [MIRROR_SOURCE_HEADER]: "cn-replica", [MIRROR_STALE_HEADER]: "true" },
        }),
    });
    const { credential, provenance } = await resolveStatusCredential(CERT_ID, {
      fetch: fetchImpl,
    });
    assert.equal(provenance.mirrorSource, "cn-replica");
    assert.equal(provenance.degraded, true);
    // 副本非权威字节:无签名对象在任何策略下都验不过(fail-closed)
    assert.equal(verifyStatusCredential(credential).valid, false);
  });
});

describe("multi-anchor — 配置与 did.json", () => {
  it("default anchor order is [primary jiaozi.io, mirror jiaozi.tech]", () => {
    assert.deepEqual([...DEFAULT_ANCHORS], [PRIMARY_ANCHOR, MIRROR_ANCHOR]);
  });

  it("honours a custom anchor list and reports which anchor answered", async () => {
    const cred = mintCredential();
    const { fetchImpl, calls } = anchorFetch({
      "https://a.example": () => {
        throw new Error("down");
      },
      "https://b.example": () => jsonResponse({}, { status: 500 }),
      "https://c.example": () => jsonResponse(cred),
    });
    const { provenance } = await resolveStatusCredential(CERT_ID, {
      anchors: ["https://a.example", "https://b.example", "https://c.example"],
      fetch: fetchImpl,
    });
    assert.equal(calls.length, 3);
    assert.equal(provenance.anchor, "https://c.example");
    assert.equal(provenance.anchorIndex, 2);
  });

  it("resolves did.json on the mirror path contract with the same fallback", async () => {
    const didDoc = { id: `did:web:www.jiaozi.io:agents:${CERT_ID}`, verificationMethod: [] };
    const { fetchImpl, calls } = anchorFetch({
      [PRIMARY_ANCHOR]: () => {
        throw new Error("primary unreachable");
      },
      [MIRROR_ANCHOR]: () =>
        jsonResponse(didDoc, {
          headers: { [MIRROR_SOURCE_HEADER]: "sg-origin", [MIRROR_STALE_HEADER]: "false" },
        }),
    });
    const { document, provenance } = await resolveDidDocument(CERT_ID, { fetch: fetchImpl });
    assert.deepEqual(document, didDoc);
    assert.equal(calls[0], `${PRIMARY_ANCHOR}/agents/${CERT_ID}/did.json`);
    assert.equal(calls[1], `${MIRROR_ANCHOR}/agents/${CERT_ID}/did.json`);
    assert.equal(provenance.viaMirror, true);
    assert.equal(provenance.degraded, false);
  });
});
