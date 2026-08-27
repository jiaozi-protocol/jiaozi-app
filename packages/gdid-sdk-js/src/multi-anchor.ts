/**
 * Multi-anchor resolution with automatic fallback (P2 多锚点 × P0 分级验证).
 *
 * did.json and jiaozi.status.v1 credentials are served by the authoritative
 * anchor https://www.jiaozi.io and byte-mirrored by https://www.jiaozi.tech
 * (pull-through cache + stale-if-error, see apps/api-cn/docs-mirror-anchor.md).
 * This module resolves against an ordered anchor list: primary first, next
 * anchor only on *transport* failure (network error / timeout / 5xx). A 2xx/4xx
 * answer is authoritative (status 404 is itself a signed unknown credential)
 * and never triggers fallback.
 *
 * 铁律(fail-closed 语义零变化):
 * - 锚点不加分:无论内容取自哪个锚,信任判定只看密钥验签结果。镜像是
 *   原字节缓存,验签与主锚同一套;镜像被投毒 → 验签不过 → 照样拒绝。
 * - 双锚全失败 → 抛 AnchorResolutionError,与单锚失败同样 fail-closed。
 * - 镜像陈旧(stale-if-error 命中)不静默当新鲜:X-Jiaozi-Mirror* 标注头
 *   解析进 provenance(stale/degraded/fetchedAt),判断权交给调用方,
 *   高危操作按既有 degraded 语义 fail-closed 拒绝。
 */

/** Authoritative primary anchor for did.json / status resolution. */
export const PRIMARY_ANCHOR = "https://www.jiaozi.io";
/** Mirror anchor (independent CN stack, byte mirror of the primary). */
export const MIRROR_ANCHOR = "https://www.jiaozi.tech";
/** Default resolution order: authoritative origin first, mirror on failure. */
export const DEFAULT_ANCHORS: readonly string[] = [PRIMARY_ANCHOR, MIRROR_ANCHOR];

/** Matches the mirror's own origin-fetch timeout (JIAOZI_STATUS_PROXY_TIMEOUT_MS). */
export const DEFAULT_ANCHOR_TIMEOUT_MS = 8000;

/** X-Jiaozi-Mirror* annotation headers (contract in docs-mirror-anchor.md §3). */
export const MIRROR_SOURCE_HEADER = "x-jiaozi-mirror";
export const MIRROR_ORIGIN_HEADER = "x-jiaozi-mirror-origin";
export const MIRROR_FETCHED_AT_HEADER = "x-jiaozi-mirror-fetched-at";
export const MIRROR_STALE_HEADER = "x-jiaozi-mirror-stale";

/**
 * `sg-origin` — raw bytes mirrored from the authoritative origin;
 * `cn-replica` — local-DB fallback copy, NOT authoritative bytes (display /
 * diagnostics only; verification decisions must not rely on it — its did.json
 * is re-serialised and its status object is unsigned, so signature / pinning
 * checks reject it anyway).
 */
export type MirrorContentSource = "sg-origin" | "cn-replica";

/** Where an answer came from and how fresh it is — never affects verification. */
export type AnchorProvenance = {
  /** Anchor base URL that produced the answer. */
  anchor: string;
  /** Position in the anchor list; 0 = primary, >0 = a fallback took over. */
  anchorIndex: number;
  /** true when the response carries X-Jiaozi-Mirror* annotation headers. */
  viaMirror: boolean;
  /** X-Jiaozi-Mirror value (when viaMirror). */
  mirrorSource?: MirrorContentSource | string;
  /** X-Jiaozi-Mirror-Origin — the origin the mirror pulls from. */
  mirrorOrigin?: string;
  /** X-Jiaozi-Mirror-Fetched-At — last *successful* origin fetch, ISO 8601. */
  fetchedAt?: string;
  /**
   * stale-if-error hit: the mirror could not reach its origin and served the
   * last good copy (X-Jiaozi-Mirror-Stale: true). Combine with `fetchedAt`
   * for the copy's age.
   */
  stale: boolean;
  /**
   * Existing degraded semantics, surfaced (never silently treated as fresh):
   * true when the content is stale or not authoritative origin bytes
   * (`cn-replica` / unknown mirror source). Callers pick their acceptance
   * window by risk; high-risk operations must fail closed on degraded answers
   * — same ladder as requireTrust online/pinned/offline.
   */
  degraded: boolean;
};

export type AnchorFailure = {
  anchor: string;
  /** e.g. "http_503", "anchor timeout after 8000ms", DNS/TLS error message. */
  reason: string;
};

/** All anchors failed at transport level — fail-closed, nothing was accepted. */
export class AnchorResolutionError extends Error {
  readonly path: string;
  readonly failures: readonly AnchorFailure[];

  constructor(path: string, failures: readonly AnchorFailure[]) {
    const detail = failures.map((f) => `${f.anchor}: ${f.reason}`).join("; ");
    super(
      `所有锚点均不可达,解析失败(fail-closed) / All anchors unreachable, resolution failed (fail-closed) — ${path} [${detail}]`,
    );
    this.name = "AnchorResolutionError";
    this.path = path;
    this.failures = failures;
  }
}

export type MultiAnchorOptions = {
  /**
   * Ordered anchor base URLs; default [primary jiaozi.io, mirror jiaozi.tech].
   * Every anchor serves the same paths — swapping the host is the whole
   * contract. Multi-anchor is outage resistance, not a trust downgrade.
   */
  anchors?: readonly string[];
  fetch?: typeof fetch;
  /** Per-anchor timeout in ms; a timed-out anchor counts as failed. */
  timeoutMs?: number;
};

export type ResolvedDidDocument = {
  /** Parsed did.json body — verify exactly as if fetched from the primary. */
  document: unknown;
  provenance: AnchorProvenance;
};

export type ResolvedStatusCredential = {
  /**
   * Parsed jiaozi.status.v1 body — feed to verifyStatusCredential /
   * requireTrust unchanged; anchor choice never relaxes verification.
   */
  credential: unknown;
  provenance: AnchorProvenance;
};

function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
}

async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error(`anchor timeout after ${timeoutMs}ms`)),
    timeoutMs,
  );
  try {
    return await fetchImpl(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function readProvenance(anchor: string, anchorIndex: number, res: Response): AnchorProvenance {
  const mirrorSource = res.headers.get(MIRROR_SOURCE_HEADER) ?? undefined;
  const viaMirror = mirrorSource !== undefined;
  const stale = res.headers.get(MIRROR_STALE_HEADER) === "true";
  return {
    anchor,
    anchorIndex,
    viaMirror,
    ...(viaMirror ? { mirrorSource } : {}),
    ...(res.headers.get(MIRROR_ORIGIN_HEADER)
      ? { mirrorOrigin: res.headers.get(MIRROR_ORIGIN_HEADER) as string }
      : {}),
    ...(res.headers.get(MIRROR_FETCHED_AT_HEADER)
      ? { fetchedAt: res.headers.get(MIRROR_FETCHED_AT_HEADER) as string }
      : {}),
    stale,
    // fail-closed marking: anything not authoritative origin bytes is degraded
    degraded: stale || (viaMirror && mirrorSource !== "sg-origin"),
  };
}

/**
 * Try each anchor in order; move on only for transport-level failures
 * (fetch rejection, timeout, 5xx, unparseable body). 2xx–4xx answers are
 * authoritative and returned as-is with provenance.
 */
async function fetchJsonFromAnchors(
  path: string,
  opts?: MultiAnchorOptions,
): Promise<{ body: unknown; provenance: AnchorProvenance }> {
  const anchors = opts?.anchors ?? DEFAULT_ANCHORS;
  if (anchors.length === 0) {
    throw new Error(
      "锚列表为空,拒绝解析(fail-closed) / Empty anchor list; refusing to resolve (fail-closed)",
    );
  }
  const fetchImpl = opts?.fetch ?? fetch;
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_ANCHOR_TIMEOUT_MS;
  const failures: AnchorFailure[] = [];

  for (let i = 0; i < anchors.length; i++) {
    const anchor = anchors[i] as string;
    let res: Response;
    try {
      res = await fetchWithTimeout(fetchImpl, joinUrl(anchor, path), timeoutMs);
    } catch (err) {
      failures.push({ anchor, reason: err instanceof Error ? err.message : String(err) });
      continue;
    }
    if (res.status >= 500) {
      failures.push({ anchor, reason: `http_${res.status}` });
      continue;
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      failures.push({ anchor, reason: "unparseable_body" });
      continue;
    }
    return { body, provenance: readProvenance(anchor, i, res) };
  }

  throw new AnchorResolutionError(path, failures);
}

/**
 * Resolve `GET {anchor}/agents/{certId}/did.json` with anchor fallback.
 * The document is returned untouched — hash pinning / key extraction runs the
 * same code path regardless of anchor.
 */
export async function resolveDidDocument(
  certId: string,
  opts?: MultiAnchorOptions,
): Promise<ResolvedDidDocument> {
  const { body, provenance } = await fetchJsonFromAnchors(
    `/agents/${encodeURIComponent(certId)}/did.json`,
    opts,
  );
  return { document: body, provenance };
}

/**
 * Resolve `GET {anchor}/api/status/{certId}` with anchor fallback. The body is
 * returned untouched for verifyStatusCredential / requireTrust — a stale or
 * replica answer is flagged in provenance but signature and freshness checks
 * stay exactly as strict (an expired stale credential still denies as
 * "expired" unless the caller explicitly opted into the offline policy).
 */
export async function resolveStatusCredential(
  certId: string,
  opts?: MultiAnchorOptions,
): Promise<ResolvedStatusCredential> {
  const { body, provenance } = await fetchJsonFromAnchors(
    `/api/status/${encodeURIComponent(certId)}`,
    opts,
  );
  return { credential: body, provenance };
}
