import type {
  AttestSummaryV1,
  CreditEventV1,
  MerkleProof,
  MultisigPolicy,
  TrustLevel,
} from "@jiaozi-protocol/gdid-core";
export {
  CREDIT_SCHEMA,
  createOwnerRoot,
  deriveAgentFromOwner,
  generateEd25519Keypair,
  hashCreditEvent,
  hashLocalCreditDetail,
  mintSigningKeyForPath,
  runAttestationChain,
  verifyMerkleProof,
  verifyStatusCredential,
} from "@jiaozi-protocol/gdid-core";

export {
  DEFAULT_STATUS_SOURCE,
  TRUST_BOUNDARY_HEADER,
  TRUST_STATUS_HEADER,
  fetchStatusCredential,
  presentationFromHeaders,
  requireTrust,
  requireTrustExpress,
  trustDenyHttpStatus,
  type FetchStatusOptions,
  type RequirableTrustLevel,
  type RequireTrustOptions,
  type TrustChecker,
  type TrustDecision,
  type TrustDenyCode,
  type TrustFreshness,
  type TrustPresentation,
  type TrustRequestLike,
  type TrustResponseLike,
  type TrustVerifyPolicy,
} from "./require-trust.js";

export {
  AnchorResolutionError,
  DEFAULT_ANCHORS,
  DEFAULT_ANCHOR_TIMEOUT_MS,
  MIRROR_ANCHOR,
  MIRROR_FETCHED_AT_HEADER,
  MIRROR_ORIGIN_HEADER,
  MIRROR_SOURCE_HEADER,
  MIRROR_STALE_HEADER,
  PRIMARY_ANCHOR,
  resolveDidDocument,
  resolveStatusCredential,
  type AnchorFailure,
  type AnchorProvenance,
  type MirrorContentSource,
  type MultiAnchorOptions,
  type ResolvedDidDocument,
  type ResolvedStatusCredential,
} from "./multi-anchor.js";

export type GdidClientOptions = {
  /** CN Front base, e.g. https://www.jiaozi.tech or http://127.0.0.1:3000 */
  baseUrl: string;
  /** Optional SG Core for authoritative resolve */
  coreUrl?: string;
  apiKey?: string;
  fetch?: typeof fetch;
};

export type RegisterInput = {
  name: string;
  ownerPubkey: string;
  capabilities?: string[];
};

export type RegisterResult = {
  agentId: string;
  did: string;
  ownerPubkey: string;
  capabilities: string[];
};

export type AttestResult = {
  certId: string;
  did: string;
  didHttpUrl?: string;
  trustLevel: TrustLevel;
  status: string;
};

export type ResolveResult = {
  kind?: string;
  certId?: string;
  did: string;
  trustLevel?: string;
  status?: string;
  agentName?: string;
  document?: unknown;
  revoked?: boolean;
  resolver?: string;
};

export type VerifyResult = {
  ok: boolean;
  did: string;
  certId?: string;
  trustLevel?: string;
  status?: string;
  revoked: boolean;
  reason?: string;
  document?: unknown;
};

function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
}

export class Gdid {
  private readonly baseUrl: string;
  private readonly coreUrl: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: GdidClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.coreUrl = (opts.coreUrl ?? opts.baseUrl).replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** Register Owner-bound agent identity (no health-check required). */
  async register(input: RegisterInput): Promise<RegisterResult> {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, "/api/register"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify({
        name: input.name,
        ownerPubkey: input.ownerPubkey,
        capabilities: input.capabilities ?? [],
      }),
    });
    const body = (await res.json()) as RegisterResult & { message?: string; error?: string };
    if (!res.ok) {
      throw new Error(body.message ?? body.error ?? `register failed (${res.status})`);
    }
    return body;
  }

  /** Submit local attest summary → certificate (maps to POST /api/verify). */
  async attest(summary: AttestSummaryV1): Promise<AttestResult> {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, "/api/verify"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify(summary),
    });
    const body = (await res.json()) as AttestResult & { message?: string; error?: string };
    if (!res.ok) {
      throw new Error(body.message ?? body.error ?? `attest failed (${res.status})`);
    }
    return body;
  }

  /** Resolve DID or cert id (prefers SG core when configured). */
  async resolve(didOrCertId: string): Promise<ResolveResult> {
    const url = joinUrl(this.coreUrl, `/api/resolve?q=${encodeURIComponent(didOrCertId)}`);
    const res = await this.fetchImpl(url);
    const body = (await res.json()) as ResolveResult & { message?: string; error?: string };
    if (!res.ok) {
      throw new Error(body.message ?? body.error ?? `resolve failed (${res.status})`);
    }
    return body;
  }

  /** Verify authenticity: resolvable + not revoked + active. */
  async verify(didOrCertId: string): Promise<VerifyResult> {
    try {
      const resolved = await this.resolve(didOrCertId);
      const revoked =
        resolved.revoked === true ||
        resolved.status === "revoked" ||
        resolved.trustLevel === "revoked";
      const active = !revoked && (resolved.status == null || resolved.status === "active");
      return {
        ok: active,
        did: resolved.did,
        certId: resolved.certId,
        trustLevel: resolved.trustLevel,
        status: resolved.status,
        revoked,
        reason: revoked ? "revoked" : active ? undefined : "inactive",
        document: resolved.document,
      };
    } catch (err) {
      return {
        ok: false,
        did: didOrCertId,
        revoked: false,
        reason: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /** Rotate authentication key on DID (Owner-bound). */
  async rotateKey(input: {
    did: string;
    currentPublicKeyMultibase: string;
    newPublicKeyMultibase: string;
  }): Promise<{ did: string; document: unknown; newPublicKeyMultibase: string }> {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, "/api/keys/rotate"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify(input),
    });
    const body = (await res.json()) as {
      did: string;
      document: unknown;
      newPublicKeyMultibase: string;
      message?: string;
      error?: string;
    };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `rotate failed (${res.status})`);
    return body;
  }

  async setMultisig(agentId: string, policy: MultisigPolicy) {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, "/api/keys/multisig"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify({ agentId, ...policy }),
    });
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `multisig failed (${res.status})`);
    return body;
  }

  /** Publish HD path public handle (never upload seed). */
  async bindHd(input: {
    path: string;
    role: "owner" | "domain" | "agent";
    publicKey: string;
    agentId?: string;
    domainId?: string;
  }) {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, "/api/hd/bind"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify(input),
    });
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `hd bind failed (${res.status})`);
    return body;
  }

  async sandboxViews(didOrCertId: string) {
    const res = await this.fetchImpl(
      joinUrl(this.baseUrl, `/api/sandbox/views?q=${encodeURIComponent(didOrCertId)}`),
    );
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `sandbox failed (${res.status})`);
    return body;
  }

  /** Submit de-identified credit event summary/summaries (hashes only). */
  async submitCredit(events: CreditEventV1 | CreditEventV1[]) {
    const res = await this.fetchImpl(joinUrl(this.baseUrl, "/api/credit/events"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify(Array.isArray(events) ? { events } : events),
    });
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `credit submit failed (${res.status})`);
    return body;
  }

  /** Seal pending credit events → Merkle root + software anchor receipt. */
  async anchorCredit(input?: { eventIds?: string[]; limit?: number }) {
    const res = await this.fetchImpl(joinUrl(this.coreUrl, "/api/credit/anchor"), {
      method: "POST",
      headers: this.authHeaders(),
      body: JSON.stringify(input ?? {}),
    });
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `credit anchor failed (${res.status})`);
    return body;
  }

  async getCreditAnchor(anchorId: string) {
    const res = await this.fetchImpl(joinUrl(this.coreUrl, `/api/credit/anchors/${encodeURIComponent(anchorId)}`));
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `anchor lookup failed (${res.status})`);
    return body;
  }

  async getCreditProof(eventId: string) {
    const res = await this.fetchImpl(
      joinUrl(this.coreUrl, `/api/credit/proof?eventId=${encodeURIComponent(eventId)}`),
    );
    const body = (await res.json()) as { message?: string; error?: string };
    if (!res.ok) throw new Error(body.message ?? body.error ?? `proof failed (${res.status})`);
    return body;
  }

  async verifyCreditProof(proof: MerkleProof) {
    const res = await this.fetchImpl(joinUrl(this.coreUrl, "/api/credit/verify-proof"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(proof),
    });
    return (await res.json()) as { ok: boolean; reason?: string };
  }

  private authHeaders(): Record<string, string> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers["X-Jiaozi-Key"] = this.apiKey;
    return headers;
  }
}

/** Convenience factory matching Spec §6.4 naming. */
export function createGdid(opts: GdidClientOptions): Gdid {
  return new Gdid(opts);
}
