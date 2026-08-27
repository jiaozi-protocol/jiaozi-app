"""Signed revocation-freshness status credential ("jiaozi.status.v1").

Python port of gdid-core `status.ts` + the key/canonical-JSON helpers it
depends on (`keys.ts` / `credit.ts`). Wire format is byte-identical to the
JS side: payload keys are camelCase, signatures are Ed25519 over
canonical_json(payload), base64url without padding.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

STATUS_SCHEMA = "jiaozi.status.v1"

# suspended = 锁定(可逆); revoked = 吊销(不可逆)。验证方对 suspended 应按"暂不可信"处理。
CERT_LIVE_STATUSES = ("active", "suspended", "revoked", "unknown")


# ---------------------------------------------------------------------------
# canonical JSON (port of gdid-core credit.ts canonicalJson)
# ---------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted object keys, no whitespace — matches the JS
    implementation byte-for-byte for JSON-representable values."""
    if value is None or not isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(x) for x in value) + "]"
    keys = sorted(value.keys())
    return "{" + ",".join(
        f"{json.dumps(k, ensure_ascii=False)}:{canonical_json(value[k])}" for k in keys
    ) + "}"


# ---------------------------------------------------------------------------
# base64url / base58btc / multibase helpers (port of gdid-core keys.ts)
# ---------------------------------------------------------------------------

def _b64url_decode(text: str) -> bytes:
    # Node's base64url decoder accepts both alphabets and missing padding.
    s = text.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _BASE58_ALPHABET[r] + out
    for b in data:
        if b != 0:
            break
        out = "1" + out
    return out


_STANDARD_MULTIKEY_RE = re.compile(r"^z6Mk[1-9A-HJ-NP-Za-km-z]+$")


def to_standard_ed25519_multibase(multibase: str) -> str:
    """把公钥归一为 Ed25519VerificationKey2020 规范要求的标准 multibase:
    multicodec 0xed01 前缀 + 32 字节原始公钥,base58btc 编码,即 z6Mk…。
    输入可以是院内格式(z + base64url 原始 32 字节)或已是标准格式(原样返回)。
    无法解析时原样返回(宁可保留证据也不静默丢 key)。"""
    if _STANDARD_MULTIKEY_RE.match(multibase):
        return multibase
    if not multibase.startswith("z"):
        return multibase
    try:
        raw = _b64url_decode(multibase[1:])
    except Exception:
        return multibase
    if len(raw) != 32:
        return multibase
    return "z" + _base58btc_encode(b"\xed\x01" + raw)


def generate_ed25519_keypair() -> dict[str, str]:
    """Returns { publicKeyMultibase, privateKeyPkcs8Base64, algorithm } —
    same shape as gdid-core generateEd25519Keypair."""
    private_key = Ed25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pkcs8 = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {
        "publicKeyMultibase": "z" + _b64url_encode(raw_public),
        "privateKeyPkcs8Base64": base64.b64encode(pkcs8).decode("ascii"),
        "algorithm": "Ed25519",
    }


def sign_with_pkcs8(private_key_pkcs8_base64: str, message: str) -> str:
    key = serialization.load_der_private_key(
        base64.b64decode(private_key_pkcs8_base64), password=None
    )
    assert isinstance(key, Ed25519PrivateKey)
    return _b64url_encode(key.sign(message.encode("utf-8")))


def verify_with_multibase(
    public_key_multibase: str, message: str, signature_base64url: str
) -> bool:
    try:
        raw = _b64url_decode(re.sub(r"^z", "", public_key_multibase))
        key = Ed25519PublicKey.from_public_bytes(raw)
        key.verify(_b64url_decode(signature_base64url), message.encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# status payload / credential (port of gdid-core status.ts)
# ---------------------------------------------------------------------------

def _iso_z(dt: datetime) -> str:
    """JS Date.toISOString() equivalent: millisecond precision, trailing Z."""
    if dt.tzinfo is None:
        dt = dt.astimezone()
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def build_status_payload(
    *,
    cert_id: str,
    did: str | None,
    status: str,
    trust_level: str | None,
    issuer: str,
    ttl_seconds: int,
    revocation_reason: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Wire-format payload dict (camelCase keys, identical to JS)."""
    now = now if now is not None else datetime.now(timezone.utc)
    now_ms = _epoch_ms(now)
    payload: dict[str, Any] = {
        "schema": STATUS_SCHEMA,
        "certId": cert_id,
        "did": did,
        "status": status,
        "trustLevel": trust_level,
        "serial": now_ms,
        "signedAt": _iso_z(now),
        "expiresAt": _iso_z(
            datetime.fromtimestamp((now_ms + ttl_seconds * 1000) / 1000, tz=timezone.utc)
        ),
        "issuer": issuer,
    }
    if revocation_reason:
        payload["revocationReason"] = revocation_reason
    return payload


def sign_status_payload(
    payload: dict[str, Any],
    private_key_pkcs8_base64: str,
    public_key_multibase: str,
) -> dict[str, Any]:
    return {
        "payload": payload,
        "signature": sign_with_pkcs8(private_key_pkcs8_base64, canonical_json(payload)),
        "publicKeyMultibase": public_key_multibase,
    }


def is_status_credential_v1(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if not isinstance(value.get("signature"), str):
        return False
    if not isinstance(value.get("publicKeyMultibase"), str):
        return False
    p = value.get("payload")
    if not isinstance(p, dict):
        return False
    serial = p.get("serial")
    return bool(
        p.get("schema") == STATUS_SCHEMA
        and isinstance(p.get("certId"), str)
        and isinstance(serial, (int, float))
        and not isinstance(serial, bool)
        and isinstance(p.get("signedAt"), str)
        and isinstance(p.get("expiresAt"), str)
        and isinstance(p.get("issuer"), str)
        and p.get("status") in CERT_LIVE_STATUSES
    )


def _parse_ms(iso: str) -> float | None:
    """Date.parse equivalent for our ISO strings; None ↔ NaN (comparison false)."""
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000
    except Exception:
        return None


def verify_status_credential(
    credential: Any,
    *,
    now: datetime | None = None,
    expected_issuer: str | None = None,
    trusted_keys: Sequence[str] | None = None,
    min_serial: int | float | None = None,
) -> dict[str, Any]:
    """Full verification for relying parties (fail-closed by default):
    shape → key pin → signature → expiry → optional issuer pin → optional
    monotonic serial floor. Returns {"valid": True, "payload": …} or
    {"valid": False, "reason": <bad_shape|bad_signature|expired|
    issuer_mismatch|untrusted_key|serial_regression>} — same codes as JS."""
    if not is_status_credential_v1(credential):
        return {"valid": False, "reason": "bad_shape"}
    payload = credential["payload"]
    public_key_multibase = credential["publicKeyMultibase"]
    if trusted_keys is not None and public_key_multibase not in trusted_keys:
        return {"valid": False, "reason": "untrusted_key"}
    if not verify_with_multibase(
        public_key_multibase, canonical_json(payload), credential["signature"]
    ):
        return {"valid": False, "reason": "bad_signature"}
    now_dt = now if now is not None else datetime.now(timezone.utc)
    expires_ms = _parse_ms(payload["expiresAt"])
    if expires_ms is not None and _epoch_ms(now_dt) > expires_ms:
        return {"valid": False, "reason": "expired"}
    if expected_issuer is not None and payload["issuer"] != expected_issuer:
        return {"valid": False, "reason": "issuer_mismatch"}
    if min_serial is not None and payload["serial"] < min_serial:
        return {"valid": False, "reason": "serial_regression"}
    return {"valid": True, "payload": payload}
