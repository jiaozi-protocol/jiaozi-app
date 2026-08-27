/** DID helpers for MVP did:web (authoritative host = SG core / jiaozi.io). */

export function buildAgentDid(coreHost: string, certId: string): string {
  const host = coreHost.trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  const id = certId.toLowerCase();
  return `did:web:${host}:agents:${id}`;
}

/** did:web:www.jiaozi.io:agents:jp-2026-000001 → host + path segments */
export function parseDidWeb(did: string): { host: string; pathSegments: string[] } | null {
  if (!did.startsWith("did:web:")) return null;
  const rest = did.slice("did:web:".length);
  const parts = rest.split(":").map((p) => decodeURIComponent(p));
  if (parts.length < 1 || !parts[0]) return null;
  return { host: parts[0], pathSegments: parts.slice(1) };
}

export function normalizeDidInput(input: string): string {
  return input.trim();
}

export function isCertId(input: string): boolean {
  // JIAOZI 为现行前缀(2026-08-08 起);JP/JJ 为历史前缀,作输入兼容且永久可解析
  return /^(JIAOZI|J[JP])-\d{4}-\d{6,9}$/i.test(input.trim());
}

/** HTTPS URL where did:web document would be published */
export function didWebHttpUrl(did: string, https = true): string | null {
  const parsed = parseDidWeb(did);
  if (!parsed) return null;
  const path =
    parsed.pathSegments.length === 0
      ? "/.well-known/did.json"
      : `/${parsed.pathSegments.join("/")}/did.json`;
  return `${https ? "https" : "http"}://${parsed.host}${path}`;
}
