/**
 * Credential → permission middleware ("凭证的价值 = 持证者的权限差").
 *
 * `requireTrust({ minLevel, behaviors })` builds a framework-agnostic checker
 * that verifies a visiting agent's jiaozi.status.v1 credential (signature +
 * freshness + live status), gates on trustLevel, and honours the agent's
 * self-declared attest.v1 `behaviorBoundary`. Pure add-on: only *calls*
 * gdid-core verification — protocol semantics untouched.
 *
 * 分级验证策略(docs/trust-root-resilience-plan.md,去域名单点):
 * `policy: "online"`(默认,现状)/ `"pinned"`(钉扎签发方公钥,验签不依赖
 * did.json)/ `"offline"`(纯本地验签,新鲜度显式降级)。fail-closed:不显式
 * 选 offline 绝不落入 offline。
 */

import {
  isStatusCredentialV1,
  toStandardEd25519Multibase,
  verifyStatusCredential,
  type BehaviorBoundaryV1,
  type StatusPayloadV1,
  type TrustLevel,
} from "@jiaozi-protocol/gdid-core";

/** Trust levels a gate can require (a credential can't "require" revoked). */
export type RequirableTrustLevel = Exclude<TrustLevel, "revoked">;

/**
 * Medal ladder, per portal mapping (CertPage.tsx):
 * bronze = software < silver = cloud_attest < gold = tee/tpm.
 */
const TRUST_RANK: Record<RequirableTrustLevel, number> = {
  software: 1,
  cloud_attest: 2,
  tee: 3,
  tpm: 3,
};

function rankOf(level: TrustLevel | null | undefined): number {
  if (!level || level === "revoked") return 0;
  return TRUST_RANK[level] ?? 0;
}

export type TrustDenyCode =
  | "no_credential"
  | "invalid_credential"
  | "expired"
  | "revoked"
  | "suspended"
  | "insufficient_level"
  | "behavior_out_of_boundary";

/**
 * Freshness of the live-status evidence behind an allow:
 * "verified" = short-TTL expiry check held (credential was fetched online
 * recently); "unverified" = offline policy skipped the check — explicit
 * downgrade marker, never emitted unless the caller opted into "offline".
 */
export type TrustFreshness = "verified" | "unverified";

export type TrustDecision =
  | {
      allowed: true;
      trustLevel: TrustLevel | null;
      certId: string;
      payload: StatusPayloadV1;
      freshness: TrustFreshness;
    }
  | {
      allowed: false;
      trustLevel: TrustLevel | null;
      reasonCode: TrustDenyCode;
      /** Human-readable, bilingual: "中文说明 / English explanation" */
      reason: string;
      certId?: string;
    };

export type TrustPresentation = {
  /** jiaozi.status.v1 credential JSON as presented by the visiting agent */
  statusCredential?: unknown;
  /** Agent's self-declared attest.v1 behaviour boundary (optional) */
  behaviorBoundary?: BehaviorBoundaryV1;
};

/**
 * Verification policy ladder (trust-root resilience plan):
 * "online"  — 现状:内嵌公钥验签 + 短时效过期检查(凭证由出示方在线新取);
 * "pinned"  — 签发方公钥本地钉扎(issuerKeys),验签不需要解析 did.json;
 *             新鲜度(过期)检查照常执行;
 * "offline" — 纯本地钉扎验签,跳过新鲜度检查,结果显式标注
 *             freshness: "unverified"(不静默降级)。
 */
export type TrustVerifyPolicy = "online" | "pinned" | "offline";

export type RequireTrustOptions = {
  /** Minimum trust level to pass; default "software" (any valid credential). */
  minLevel?: RequirableTrustLevel;
  /**
   * Behaviours this gate exercises (e.g. ["write"]). If the agent declared a
   * behaviorBoundary with `permissions`, every behaviour must be inside it;
   * an absent boundary declares no constraint and passes.
   */
  behaviors?: string[];
  /** Passed through to gdid-core verifyStatusCredential (issuer/key pinning …). */
  verify?: {
    now?: Date;
    expectedIssuer?: string;
    trustedKeys?: readonly string[];
    minSerial?: number;
  };
  /** Verification policy; default "online" (exact pre-existing behaviour). */
  policy?: TrustVerifyPolicy;
  /**
   * Issuer public keys this gate trusts, standard multikey (z6Mk…, as
   * published in did.json / GET /api/status-key) or the historical
   * z+base64url form — both normalised via toStandardEd25519Multibase.
   * Required (fail-closed, throws at build time) for "pinned"/"offline".
   */
  issuerKeys?: readonly string[];
};

export type TrustChecker = (presentation?: TrustPresentation | null) => TrustDecision;

function deny(
  reasonCode: TrustDenyCode,
  reason: string,
  extra?: { trustLevel?: TrustLevel | null; certId?: string },
): TrustDecision {
  return {
    allowed: false,
    reasonCode,
    reason,
    trustLevel: extra?.trustLevel ?? null,
    ...(extra?.certId ? { certId: extra.certId } : {}),
  };
}

const LEVEL_LABEL: Record<RequirableTrustLevel, string> = {
  software: "software(铜/Bronze)",
  cloud_attest: "cloud_attest(银/Silver)",
  tee: "tee(金/Gold)",
  tpm: "tpm(金/Gold)",
};

/** offline 跳过新鲜度:epoch 0 让 verifyStatusCredential 的过期检查恒不触发。 */
const SKIP_EXPIRY_NOW = new Date(0);

/**
 * Build a framework-agnostic trust gate. Returns a pure function:
 * presentation in → { allowed, trustLevel, reason, reasonCode } out.
 */
export function requireTrust(options?: RequireTrustOptions): TrustChecker {
  const minLevel: RequirableTrustLevel = options?.minLevel ?? "software";
  const requiredRank = TRUST_RANK[minLevel];
  const behaviors = options?.behaviors ?? [];
  const policy: TrustVerifyPolicy = options?.policy ?? "online";
  const pinnedKeys = (options?.issuerKeys ?? []).map(toStandardEd25519Multibase);
  if (policy !== "online" && pinnedKeys.length === 0) {
    // fail-closed at build time: a pin-based gate without pins verifies nothing
    throw new Error(
      `requireTrust: policy "${policy}" 必须提供 issuerKeys(签发方公钥钉扎),缺省即拒绝 / policy "${policy}" requires issuerKeys (issuer key pinning); refusing to build an unpinned gate`,
    );
  }
  const freshness: TrustFreshness = policy === "offline" ? "unverified" : "verified";

  return (presentation) => {
    const credential = presentation?.statusCredential;
    if (credential === undefined || credential === null) {
      return deny(
        "no_credential",
        "未出示状态凭证,仅可使用公开只读能力 / No status credential presented; only public read-only capabilities are available",
      );
    }

    if (policy !== "online") {
      if (!isStatusCredentialV1(credential)) {
        return deny(
          "invalid_credential",
          "状态凭证无效(bad_shape),验签或格式未通过 / Status credential invalid (bad_shape); signature or shape check failed",
        );
      }
      // 钉扎核对:内嵌公钥必须命中钉扎集合(编码归一后比较),否则拒绝
      const embeddedKey = toStandardEd25519Multibase(credential.publicKeyMultibase);
      if (!pinnedKeys.includes(embeddedKey)) {
        return deny(
          "invalid_credential",
          "凭证内嵌公钥与钉扎的签发方公钥不匹配(pinned_key_mismatch),拒绝验签 / Credential's embedded key matches no pinned issuer key (pinned_key_mismatch); refusing to verify",
        );
      }
    }

    const result = verifyStatusCredential(
      credential,
      policy === "offline" ? { ...options?.verify, now: SKIP_EXPIRY_NOW } : options?.verify,
    );
    if (!result.valid) {
      if (result.reason === "expired") {
        return deny(
          "expired",
          "状态凭证已过期(status.v1 为短时效凭证),请向签发方获取新凭证 / Status credential expired (status.v1 is short-TTL); fetch a fresh one from the issuer",
        );
      }
      return deny(
        "invalid_credential",
        `状态凭证无效(${result.reason}),验签或格式未通过 / Status credential invalid (${result.reason}); signature or shape check failed`,
      );
    }

    const payload = result.payload;
    if (payload.status === "revoked") {
      return deny(
        "revoked",
        "凭证已被吊销(不可逆),拒绝访问 / Credential has been revoked (irreversible); access denied",
        { trustLevel: payload.trustLevel, certId: payload.certId },
      );
    }
    if (payload.status === "suspended") {
      return deny(
        "suspended",
        "凭证处于锁定(暂停)状态,暂不可信 / Credential is suspended (locked); temporarily not trusted",
        { trustLevel: payload.trustLevel, certId: payload.certId },
      );
    }
    if (payload.status !== "active") {
      return deny(
        "invalid_credential",
        "凭证状态未知,按不可信处理 / Credential live status is unknown; treated as untrusted (fail-closed)",
        { trustLevel: payload.trustLevel, certId: payload.certId },
      );
    }

    if (rankOf(payload.trustLevel) < requiredRank) {
      return deny(
        "insufficient_level",
        `信任等级不足:需要 ${LEVEL_LABEL[minLevel]} 及以上,当前为 ${payload.trustLevel ?? "无"} / Insufficient trust level: requires ${LEVEL_LABEL[minLevel]} or above, credential carries ${payload.trustLevel ?? "none"}`,
        { trustLevel: payload.trustLevel, certId: payload.certId },
      );
    }

    if (behaviors.length > 0) {
      const permitted = presentation?.behaviorBoundary?.permissions;
      if (Array.isArray(permitted)) {
        const outside = behaviors.filter((b) => !permitted.includes(b));
        if (outside.length > 0) {
          return deny(
            "behavior_out_of_boundary",
            `请求行为超出该 agent 自述的行为边界(越界:${outside.join(", ")}) / Requested behaviour falls outside the agent's declared behaviour boundary (out of bounds: ${outside.join(", ")})`,
            { trustLevel: payload.trustLevel, certId: payload.certId },
          );
        }
      }
    }

    return {
      allowed: true,
      trustLevel: payload.trustLevel,
      certId: payload.certId,
      payload,
      freshness,
    };
  };
}

/** Suggested HTTP status for a deny code: 401 when nothing presented, else 403. */
export function trustDenyHttpStatus(code: TrustDenyCode): number {
  return code === "no_credential" ? 401 : 403;
}

/** Primary status anchor (SG core). Mirror anchors (e.g. jiaozi.tech, P2) are drop-in. */
export const DEFAULT_STATUS_SOURCE = "https://core.jiaozi.io";

export type FetchStatusOptions = {
  /** Status endpoint base URL — configurable anchor, defaults to the primary. */
  statusSource?: string;
  fetch?: typeof fetch;
};

/**
 * Fetch a fresh jiaozi.status.v1 credential for `certId` from a configurable
 * status source (`GET {statusSource}/api/status/{certId}`). Pairs with the
 * "pinned" policy: signature trust is anchored locally in the pinned key, so
 * the freshness source no longer has to be the primary domain — point
 * `statusSource` at a mirror anchor and verification survives a jiaozi.io
 * outage. Unknown cert ids still return a *signed* unknown-status credential
 * (fail-closed downstream), so the body is returned as-is for the checker.
 */
export async function fetchStatusCredential(
  certId: string,
  opts?: FetchStatusOptions,
): Promise<unknown> {
  const base = (opts?.statusSource ?? DEFAULT_STATUS_SOURCE).replace(/\/$/, "");
  const fetchImpl = opts?.fetch ?? fetch;
  const res = await fetchImpl(`${base}/api/status/${encodeURIComponent(certId)}`);
  return await res.json();
}

function parseHeaderJson(raw: string): unknown {
  const text = raw.trim();
  if (!text) return undefined;
  if (text.startsWith("{")) {
    try {
      return JSON.parse(text);
    } catch {
      return undefined;
    }
  }
  // base64 / base64url encoded JSON (safe for HTTP header transport)
  try {
    const decoded = Buffer.from(text, "base64").toString("utf8");
    return JSON.parse(decoded);
  } catch {
    return undefined;
  }
}

export const TRUST_STATUS_HEADER = "x-jiaozi-status";
export const TRUST_BOUNDARY_HEADER = "x-jiaozi-boundary";

/**
 * Extract a presentation from HTTP headers:
 * `x-jiaozi-status` — status.v1 credential JSON, raw or base64url-encoded;
 * `x-jiaozi-boundary` — self-declared attest.v1 behaviorBoundary, same encodings.
 */
export function presentationFromHeaders(
  headers: Record<string, string | string[] | undefined>,
): TrustPresentation {
  const pick = (name: string): string | undefined => {
    const v = headers[name] ?? headers[name.toLowerCase()];
    return Array.isArray(v) ? v[0] : v;
  };
  const presentation: TrustPresentation = {};
  const statusRaw = pick(TRUST_STATUS_HEADER);
  if (statusRaw) presentation.statusCredential = parseHeaderJson(statusRaw);
  const boundaryRaw = pick(TRUST_BOUNDARY_HEADER);
  if (boundaryRaw) {
    const parsed = parseHeaderJson(boundaryRaw);
    if (parsed && typeof parsed === "object") {
      presentation.behaviorBoundary = parsed as BehaviorBoundaryV1;
    }
  }
  return presentation;
}

/** Minimal request/response shapes so the middleware needs no framework types. */
export type TrustRequestLike = {
  headers: Record<string, string | string[] | undefined>;
  /** Decision is attached here for downstream handlers. */
  jiaoziTrust?: TrustDecision;
};

export type TrustResponseLike = {
  status(code: number): { json(body: unknown): unknown };
};

/**
 * Express-style middleware: reads the credential from headers, attaches the
 * decision to `req.jiaoziTrust`, and answers 401/403 with a readable bilingual
 * reason on deny.
 */
export function requireTrustExpress(
  options?: RequireTrustOptions,
): (req: TrustRequestLike, res: TrustResponseLike, next: () => void) => void {
  const check = requireTrust(options);
  return (req, res, next) => {
    const decision = check(presentationFromHeaders(req.headers));
    req.jiaoziTrust = decision;
    if (decision.allowed) {
      next();
      return;
    }
    res.status(trustDenyHttpStatus(decision.reasonCode)).json({
      error: decision.reasonCode,
      reason: decision.reason,
      trustLevel: decision.trustLevel,
      ...(decision.certId ? { certId: decision.certId } : {}),
    });
  };
}
