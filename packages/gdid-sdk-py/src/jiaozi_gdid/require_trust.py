"""Credential → permission middleware ("凭证的价值 = 持证者的权限差").

`require_trust(min_level=…, behaviors=…)` builds a framework-agnostic checker
that verifies a visiting agent's jiaozi.status.v1 credential (signature +
freshness + live status), gates on trustLevel, and honours the agent's
self-declared attest.v1 `behaviorBoundary`. Pure add-on: only *calls* the
gdid-core-aligned verification in `status.py` — protocol semantics untouched.

分级验证策略(docs/trust-root-resilience-plan.md,去域名单点):
`policy="online"`(默认,现状)/ `"pinned"`(钉扎签发方公钥,验签不依赖
did.json)/ `"offline"`(纯本地验签,新鲜度显式降级)。fail-closed:不显式
选 offline 绝不落入 offline。

Semantics are a line-for-line port of gdid-sdk-js `require-trust.ts`; reason
strings are copied verbatim (中英双语).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from .status import (
    _b64url_decode,
    is_status_credential_v1,
    to_standard_ed25519_multibase,
    verify_status_credential,
)

# Medal ladder, per portal mapping (CertPage.tsx):
# bronze = software < silver = cloud_attest < gold = tee/tpm.
TRUST_RANK: dict[str, int] = {
    "software": 1,
    "cloud_attest": 2,
    "tee": 3,
    "tpm": 3,
}


def _rank_of(level: str | None) -> int:
    if not level or level == "revoked":
        return 0
    return TRUST_RANK.get(level, 0)


# Deny codes: no_credential / invalid_credential / expired / revoked /
# suspended / insufficient_level / behavior_out_of_boundary — same as JS.

_LEVEL_LABEL: dict[str, str] = {
    "software": "software(铜/Bronze)",
    "cloud_attest": "cloud_attest(银/Silver)",
    "tee": "tee(金/Gold)",
    "tpm": "tpm(金/Gold)",
}

# offline 跳过新鲜度:epoch 0 让 verify_status_credential 的过期检查恒不触发。
_SKIP_EXPIRY_NOW = datetime.fromtimestamp(0, tz=timezone.utc)


@dataclass
class TrustDecision:
    """{ allowed, trustLevel, reason, reasonCode } — snake_case attributes;
    `to_dict()` emits the JS camelCase wire shape."""

    allowed: bool
    trust_level: str | None = None
    cert_id: str | None = None
    payload: dict[str, Any] | None = None
    #: "verified" = short-TTL expiry check held; "unverified" = offline policy
    #: skipped it — explicit downgrade marker, never emitted unless the caller
    #: opted into "offline".
    freshness: str | None = None
    reason_code: str | None = None
    #: Human-readable, bilingual: "中文说明 / English explanation"
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.allowed:
            d: dict[str, Any] = {
                "allowed": True,
                "trustLevel": self.trust_level,
                "certId": self.cert_id,
                "payload": self.payload,
                "freshness": self.freshness,
            }
        else:
            d = {
                "allowed": False,
                "trustLevel": self.trust_level,
                "reasonCode": self.reason_code,
                "reason": self.reason,
            }
            if self.cert_id:
                d["certId"] = self.cert_id
        return d


@dataclass
class TrustPresentation:
    #: jiaozi.status.v1 credential JSON (parsed dict) as presented by the agent
    status_credential: Any = None
    #: Agent's self-declared attest.v1 behaviour boundary (optional)
    behavior_boundary: dict[str, Any] | None = None


TrustChecker = Callable[..., TrustDecision]


def _deny(
    reason_code: str,
    reason: str,
    *,
    trust_level: str | None = None,
    cert_id: str | None = None,
) -> TrustDecision:
    return TrustDecision(
        allowed=False,
        reason_code=reason_code,
        reason=reason,
        trust_level=trust_level,
        cert_id=cert_id,
    )


def _coerce_presentation(presentation: Any) -> TrustPresentation:
    if presentation is None:
        return TrustPresentation()
    if isinstance(presentation, TrustPresentation):
        return presentation
    if isinstance(presentation, Mapping):
        return TrustPresentation(
            status_credential=presentation.get("status_credential")
            if "status_credential" in presentation
            else presentation.get("statusCredential"),
            behavior_boundary=presentation.get("behavior_boundary")
            if "behavior_boundary" in presentation
            else presentation.get("behaviorBoundary"),
        )
    return TrustPresentation()


def require_trust(
    *,
    min_level: str = "software",
    behaviors: Sequence[str] | None = None,
    verify: Mapping[str, Any] | None = None,
    policy: str = "online",
    issuer_keys: Sequence[str] | None = None,
) -> TrustChecker:
    """Build a framework-agnostic trust gate. Returns a pure function:
    presentation in → TrustDecision (allowed, trust_level, reason, reason_code) out.

    - min_level: minimum trust level to pass; default "software".
    - behaviors: behaviours this gate exercises (e.g. ["write"]). If the agent
      declared a behaviorBoundary with `permissions`, every behaviour must be
      inside it; an absent boundary declares no constraint and passes.
    - verify: passed through to verify_status_credential
      ({"now", "expected_issuer", "trusted_keys", "min_serial"}).
    - policy: "online" (default) / "pinned" / "offline".
    - issuer_keys: pinned issuer public keys (z6Mk… standard or historical
      z+base64url form). Required (fail-closed, raises at build time) for
      "pinned"/"offline".
    """
    required_rank = TRUST_RANK[min_level]
    behaviors = list(behaviors or [])
    verify_opts = dict(verify or {})
    pinned_keys = [to_standard_ed25519_multibase(k) for k in (issuer_keys or [])]
    if policy != "online" and len(pinned_keys) == 0:
        # fail-closed at build time: a pin-based gate without pins verifies nothing
        raise ValueError(
            f'require_trust: policy "{policy}" 必须提供 issuer_keys(签发方公钥钉扎),缺省即拒绝'
            f' / policy "{policy}" requires issuerKeys (issuer key pinning);'
            " refusing to build an unpinned gate"
        )
    freshness = "unverified" if policy == "offline" else "verified"

    def check(presentation: Any = None) -> TrustDecision:
        p = _coerce_presentation(presentation)
        credential = p.status_credential
        if credential is None:
            return _deny(
                "no_credential",
                "未出示状态凭证,仅可使用公开只读能力 / No status credential presented;"
                " only public read-only capabilities are available",
            )

        if policy != "online":
            if not is_status_credential_v1(credential):
                return _deny(
                    "invalid_credential",
                    "状态凭证无效(bad_shape),验签或格式未通过 / Status credential invalid"
                    " (bad_shape); signature or shape check failed",
                )
            # 钉扎核对:内嵌公钥必须命中钉扎集合(编码归一后比较),否则拒绝
            embedded_key = to_standard_ed25519_multibase(credential["publicKeyMultibase"])
            if embedded_key not in pinned_keys:
                return _deny(
                    "invalid_credential",
                    "凭证内嵌公钥与钉扎的签发方公钥不匹配(pinned_key_mismatch),拒绝验签"
                    " / Credential's embedded key matches no pinned issuer key"
                    " (pinned_key_mismatch); refusing to verify",
                )

        effective_verify = dict(verify_opts)
        if policy == "offline":
            effective_verify["now"] = _SKIP_EXPIRY_NOW
        result = verify_status_credential(credential, **effective_verify)
        if not result["valid"]:
            if result["reason"] == "expired":
                return _deny(
                    "expired",
                    "状态凭证已过期(status.v1 为短时效凭证),请向签发方获取新凭证"
                    " / Status credential expired (status.v1 is short-TTL);"
                    " fetch a fresh one from the issuer",
                )
            return _deny(
                "invalid_credential",
                f"状态凭证无效({result['reason']}),验签或格式未通过 / Status credential"
                f" invalid ({result['reason']}); signature or shape check failed",
            )

        payload = result["payload"]
        trust_level = payload.get("trustLevel")
        cert_id = payload.get("certId")
        if payload["status"] == "revoked":
            return _deny(
                "revoked",
                "凭证已被吊销(不可逆),拒绝访问 / Credential has been revoked"
                " (irreversible); access denied",
                trust_level=trust_level,
                cert_id=cert_id,
            )
        if payload["status"] == "suspended":
            return _deny(
                "suspended",
                "凭证处于锁定(暂停)状态,暂不可信 / Credential is suspended (locked);"
                " temporarily not trusted",
                trust_level=trust_level,
                cert_id=cert_id,
            )
        if payload["status"] != "active":
            return _deny(
                "invalid_credential",
                "凭证状态未知,按不可信处理 / Credential live status is unknown;"
                " treated as untrusted (fail-closed)",
                trust_level=trust_level,
                cert_id=cert_id,
            )

        if _rank_of(trust_level) < required_rank:
            return _deny(
                "insufficient_level",
                f"信任等级不足:需要 {_LEVEL_LABEL[min_level]} 及以上,当前为"
                f" {trust_level if trust_level is not None else '无'}"
                f" / Insufficient trust level: requires {_LEVEL_LABEL[min_level]} or"
                f" above, credential carries"
                f" {trust_level if trust_level is not None else 'none'}",
                trust_level=trust_level,
                cert_id=cert_id,
            )

        if behaviors:
            boundary = p.behavior_boundary
            permitted = boundary.get("permissions") if isinstance(boundary, Mapping) else None
            if isinstance(permitted, list):
                outside = [b for b in behaviors if b not in permitted]
                if outside:
                    return _deny(
                        "behavior_out_of_boundary",
                        f"请求行为超出该 agent 自述的行为边界(越界:{', '.join(outside)})"
                        " / Requested behaviour falls outside the agent's declared"
                        f" behaviour boundary (out of bounds: {', '.join(outside)})",
                        trust_level=trust_level,
                        cert_id=cert_id,
                    )

        return TrustDecision(
            allowed=True,
            trust_level=trust_level,
            cert_id=cert_id,
            payload=payload,
            freshness=freshness,
        )

    return check


def trust_deny_http_status(code: str) -> int:
    """Suggested HTTP status for a deny code: 401 when nothing presented, else 403."""
    return 401 if code == "no_credential" else 403


#: Primary status anchor (SG core). Mirror anchors (e.g. jiaozi.tech, P2) are drop-in.
DEFAULT_STATUS_SOURCE = "https://core.jiaozi.io"


def fetch_status_credential(
    cert_id: str,
    *,
    status_source: str | None = None,
    client: Any = None,
    timeout: float = 30.0,
) -> Any:
    """Fetch a fresh jiaozi.status.v1 credential for `cert_id` from a
    configurable status source (`GET {status_source}/api/status/{cert_id}`).
    Pairs with the "pinned" policy: signature trust is anchored locally in the
    pinned key, so the freshness source no longer has to be the primary domain.
    Unknown cert ids still return a *signed* unknown-status credential
    (fail-closed downstream), so the body is returned as-is for the checker.

    `client` accepts any httpx.Client-compatible object (injectable for tests).
    """
    import urllib.parse

    import httpx

    base = (status_source or DEFAULT_STATUS_SOURCE).rstrip("/")
    url = f"{base}/api/status/{urllib.parse.quote(cert_id, safe='')}"
    if client is not None:
        return client.get(url).json()
    with httpx.Client(timeout=timeout) as own_client:
        return own_client.get(url).json()


def _parse_header_json(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            return json.loads(text)
        except Exception:
            return None
    # base64 / base64url encoded JSON (safe for HTTP header transport)
    try:
        return json.loads(_b64url_decode(text).decode("utf-8"))
    except Exception:
        return None


TRUST_STATUS_HEADER = "x-jiaozi-status"
TRUST_BOUNDARY_HEADER = "x-jiaozi-boundary"


def presentation_from_headers(headers: Mapping[str, Any]) -> TrustPresentation:
    """Extract a presentation from HTTP headers:
    `x-jiaozi-status` — status.v1 credential JSON, raw or base64url-encoded;
    `x-jiaozi-boundary` — self-declared attest.v1 behaviorBoundary, same encodings.
    """

    def pick(name: str) -> str | None:
        v = headers.get(name)
        if v is None:
            low = name.lower()
            for k, val in headers.items():
                if isinstance(k, str) and k.lower() == low:
                    v = val
                    break
        if isinstance(v, (list, tuple)):
            v = v[0] if v else None
        return v if isinstance(v, str) else None

    presentation = TrustPresentation()
    status_raw = pick(TRUST_STATUS_HEADER)
    if status_raw:
        presentation.status_credential = _parse_header_json(status_raw)
    boundary_raw = pick(TRUST_BOUNDARY_HEADER)
    if boundary_raw:
        parsed = _parse_header_json(boundary_raw)
        if isinstance(parsed, dict):
            presentation.behavior_boundary = parsed
    return presentation
