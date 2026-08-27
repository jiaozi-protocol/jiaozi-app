"""W3C VC export helpers — structure & status layer (pragmatic tier, #26).

Companion to the api-sg VC export (``GET /api/certs/{certId}/vc``,
VC 2.0 + DataIntegrityProof ``eddsa-rdfc-2022``) and its Bitstring Status
List endpoint (``GET /api/status-list/revocation``).

Scope (deliberate): this module does **not** perform JSON-LD (RDFC-1.0)
canonicalization or DataIntegrityProof signature verification — that
requires a full RDF stack (pyld etc.), which is too heavy a dependency for
this SDK. For full cryptographic verification of the exported VC use a
general-purpose VC library that supports ``eddsa-rdfc-2022``, e.g.
``openvc-core[data-integrity]`` (Python) or ``@digitalbazaar/vc`` (JS).
This SDK provides the structure & status layer:

- :func:`fetch_vc` — fetch the exported VC (404/410/501 raise
  :class:`VcExportError` with the server's body preserved);
- :func:`validate_vc_structure` — non-cryptographic envelope checks
  (contexts / types / proof shape / status entries);
- :func:`decode_status_list_bitstring` / :func:`status_list_bit` —
  Bitstring Status List v1.0 decoding (multibase base64url → GZIP →
  MSB-first bitstring);
- :func:`check_bitstring_entry` — dereference a ``BitstringStatusListEntry``
  and read this credential's bit;
- :func:`check_vc_status` — walk both credentialStatus channels
  (``JiaoziStatusV1Entry`` = signed 60-second freshness, verified via
  :func:`jiaozi_gdid.status.verify_status_credential`;
  ``BitstringStatusListEntry`` = minute-level standard list) and combine
  them fail-closed (revoked on either channel ⇒ revoked).

新鲜度纪律:BitstringStatusList 是分钟级列表,**不替代 status.v1 的 60 秒
新鲜度**;高风险场景(资金/合同/数据披露)仍须走 require_trust /
``/api/status/{certId}`` 通道。
"""

from __future__ import annotations

import gzip
import urllib.parse
from typing import Any, Mapping, Sequence

from .require_trust import DEFAULT_STATUS_SOURCE
from .status import _b64url_decode, verify_status_credential

VC_V2_CONTEXT_URL = "https://www.w3.org/ns/credentials/v2"
JIAOZI_ATTEST_V1_CONTEXT_URL = "https://www.jiaozi.io/ns/attest/v1.json"

#: 规范最小位串长度(herd privacy 下限):131,072 位 = 16KB
MIN_BITSTRING_BITS = 131_072


class VcExportError(RuntimeError):
    """Non-200 answer from the VC export endpoint.

    ``status_code`` / ``body`` preserve the server response — 410 means the
    credential is revoked (no VC is exported for revoked credentials), 501
    means the deployment has no signing key configured.
    """

    def __init__(self, status_code: int, body: Any):
        self.status_code = status_code
        self.body = body
        detail = body.get("error") if isinstance(body, Mapping) else body
        super().__init__(f"vc export failed (HTTP {status_code}): {detail}")


def fetch_vc(
    cert_id: str,
    *,
    core_url: str | None = None,
    client: Any = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """GET ``{core_url}/api/certs/{cert_id}/vc`` → signed VC dict (HTTP 200).

    ``client`` accepts any httpx.Client-compatible object (injectable for
    tests); non-200 raises :class:`VcExportError`.
    """
    import httpx

    base = (core_url or DEFAULT_STATUS_SOURCE).rstrip("/")
    url = f"{base}/api/certs/{urllib.parse.quote(cert_id, safe='')}/vc"
    if client is not None:
        r = client.get(url)
    else:
        with httpx.Client(timeout=timeout) as own_client:
            r = own_client.get(url)
    body = r.json()
    if r.status_code != 200:
        raise VcExportError(r.status_code, body)
    return body


# ---------------------------------------------------------------------------
# structure validation (non-cryptographic)
# ---------------------------------------------------------------------------

def credential_status_entries(vc: Mapping[str, Any]) -> list[dict[str, Any]]:
    """credentialStatus normalized to a list (VC 2.0 allows object or array)."""
    raw = vc.get("credentialStatus")
    if isinstance(raw, Mapping):
        return [dict(raw)]
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        return [dict(e) for e in raw if isinstance(e, Mapping)]
    return []


def validate_vc_structure(vc: Any) -> list[str]:
    """Envelope checks for a ``JiaoziAttestationCredential`` export.

    Returns a list of human-readable problems; empty list = structurally
    valid. **Not** a signature check — see module docstring.
    """
    problems: list[str] = []
    if not isinstance(vc, Mapping):
        return ["vc must be a JSON object"]

    ctx = vc.get("@context")
    if not isinstance(ctx, list) or not ctx or ctx[0] != VC_V2_CONTEXT_URL:
        problems.append(f"@context must be a list starting with {VC_V2_CONTEXT_URL}")
    elif JIAOZI_ATTEST_V1_CONTEXT_URL not in ctx:
        problems.append(f"@context must include {JIAOZI_ATTEST_V1_CONTEXT_URL}")

    types = vc.get("type")
    if not isinstance(types, list) or "VerifiableCredential" not in types:
        problems.append("type must be a list containing VerifiableCredential")
    elif "JiaoziAttestationCredential" not in types:
        problems.append("type must contain JiaoziAttestationCredential")

    issuer = vc.get("issuer")
    if not (isinstance(issuer, str) and issuer.startswith("did:")):
        problems.append("issuer must be a DID string")

    if not isinstance(vc.get("validFrom"), str):
        problems.append("validFrom must be an ISO datetime string")

    subject = vc.get("credentialSubject")
    if not isinstance(subject, Mapping):
        problems.append("credentialSubject must be an object")
    else:
        if subject.get("type") != "JiaoziAgentAttestation":
            problems.append("credentialSubject.type must be JiaoziAgentAttestation")
        if not isinstance(subject.get("trustLevel"), str):
            problems.append("credentialSubject.trustLevel missing")

    proof = vc.get("proof")
    if isinstance(proof, list):
        # 评估备忘实测坑 2:导出层只发单个 proof 对象;数组视为结构不符
        problems.append("proof must be a single object, not an array (proof set)")
    elif not isinstance(proof, Mapping):
        problems.append("proof must be an object")
    else:
        if proof.get("type") != "DataIntegrityProof":
            problems.append("proof.type must be DataIntegrityProof")
        if proof.get("cryptosuite") != "eddsa-rdfc-2022":
            problems.append("proof.cryptosuite must be eddsa-rdfc-2022")
        if proof.get("proofPurpose") != "assertionMethod":
            problems.append("proof.proofPurpose must be assertionMethod")
        if not isinstance(proof.get("verificationMethod"), str):
            problems.append("proof.verificationMethod missing")
        if not isinstance(proof.get("proofValue"), str):
            problems.append("proof.proofValue missing")

    entries = credential_status_entries(vc)
    if not entries:
        problems.append("credentialStatus missing")
    for entry in entries:
        etype = entry.get("type")
        if etype == "BitstringStatusListEntry":
            if not isinstance(entry.get("statusListCredential"), str):
                problems.append("BitstringStatusListEntry.statusListCredential missing")
            idx = entry.get("statusListIndex")
            if not (isinstance(idx, str) and idx.isdigit()):
                problems.append("BitstringStatusListEntry.statusListIndex must be a digit string")
        elif etype == "JiaoziStatusV1Entry":
            if not isinstance(entry.get("id"), str):
                problems.append("JiaoziStatusV1Entry.id (status endpoint URL) missing")
        else:
            problems.append(f"unknown credentialStatus type: {etype!r}")

    return problems


# ---------------------------------------------------------------------------
# Bitstring Status List v1.0 decoding
# ---------------------------------------------------------------------------

def decode_status_list_bitstring(encoded_list: str) -> bytes:
    """``encodedList`` → raw bitstring bytes.

    Per spec: multibase base64url (leading ``u``, no padding) wrapping a
    GZIP-compressed bitstring. Fail-closed: anything malformed raises.
    """
    if not isinstance(encoded_list, str) or not encoded_list.startswith("u"):
        raise ValueError("encodedList must be multibase base64url (leading 'u')")
    return gzip.decompress(_b64url_decode(encoded_list[1:]))


def status_list_bit(bits: bytes, index: int) -> bool:
    """Read bit ``index`` (MSB-first: index 0 = highest bit of first byte).

    Fail-closed: an index outside the bitstring raises ``ValueError``
    (per spec the verifier must reject, not assume 0).
    """
    if not isinstance(index, int) or index < 0 or index >= len(bits) * 8:
        raise ValueError(f"statusListIndex {index!r} outside bitstring of {len(bits) * 8} bits")
    return bool(bits[index >> 3] & (0x80 >> (index & 7)))


def check_bitstring_entry(
    entry: Mapping[str, Any],
    *,
    client: Any = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Dereference a ``BitstringStatusListEntry`` and read this VC's bit.

    Returns ``{"set", "statusPurpose", "statusListIndex",
    "statusListCredential", "listValidFrom", "listValidUntil"}``.
    Structure layer only — the fetched list credential's own
    DataIntegrityProof is **not** cryptographically verified here (use a
    general-purpose VC library for that; see module docstring).
    """
    import httpx

    if entry.get("type") != "BitstringStatusListEntry":
        raise ValueError("entry.type must be BitstringStatusListEntry")
    url = entry.get("statusListCredential")
    if not isinstance(url, str) or not url:
        raise ValueError("entry.statusListCredential missing")
    raw_index = entry.get("statusListIndex")
    if not (isinstance(raw_index, str) and raw_index.isdigit()):
        raise ValueError("entry.statusListIndex must be a digit string")
    index = int(raw_index)

    if client is not None:
        r = client.get(url)
    else:
        with httpx.Client(timeout=timeout) as own_client:
            r = own_client.get(url)
    if r.status_code != 200:
        raise VcExportError(r.status_code, r.json())
    credential = r.json()

    subject = credential.get("credentialSubject")
    if not isinstance(subject, Mapping) or subject.get("type") != "BitstringStatusList":
        raise ValueError("statusListCredential.credentialSubject is not a BitstringStatusList")
    list_purpose = subject.get("statusPurpose")
    entry_purpose = entry.get("statusPurpose")
    if entry_purpose is not None and list_purpose != entry_purpose:
        raise ValueError(
            f"statusPurpose mismatch: entry={entry_purpose!r} list={list_purpose!r}"
        )
    bits = decode_status_list_bitstring(subject.get("encodedList"))
    return {
        "set": status_list_bit(bits, index),
        "statusPurpose": list_purpose,
        "statusListIndex": index,
        "statusListCredential": url,
        "listValidFrom": credential.get("validFrom"),
        "listValidUntil": credential.get("validUntil"),
    }


# ---------------------------------------------------------------------------
# combined status check (both channels, fail-closed)
# ---------------------------------------------------------------------------

def check_vc_status(
    vc: Mapping[str, Any],
    *,
    client: Any = None,
    timeout: float = 30.0,
    verify: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Walk both credentialStatus channels of an exported VC.

    - ``JiaoziStatusV1Entry`` → fetch the signed jiaozi.status.v1 credential
      and verify it with :func:`verify_status_credential` (``verify`` kwargs
      are passed through: ``expected_issuer`` / ``trusted_keys`` /
      ``min_serial`` / ``now``);
    - ``BitstringStatusListEntry`` → :func:`check_bitstring_entry`.

    Combination is fail-closed: **revoked on either channel ⇒ revoked**.
    ``status`` is the live status from the (verified) status.v1 channel when
    available — that channel is 60-second fresh and also carries
    ``suspended``; the bitstring channel is minute-level and revocation-only.

    Returns ``{"revoked", "status", "sources": {"jiaoziStatusV1",
    "bitstringStatusList"}}``; each source is either a result dict or
    ``{"error": …}`` (network/shape failures are reported, not swallowed).
    """
    import httpx

    sources: dict[str, Any] = {}
    revoked = False
    status: str | None = None

    def get(url: str) -> Any:
        if client is not None:
            return client.get(url)
        with httpx.Client(timeout=timeout) as own_client:
            return own_client.get(url)

    for entry in credential_status_entries(vc):
        etype = entry.get("type")
        if etype == "JiaoziStatusV1Entry":
            try:
                credential = get(entry["id"]).json()
                result = verify_status_credential(credential, **dict(verify or {}))
                if result["valid"]:
                    payload = result["payload"]
                    status = payload.get("status")
                    if status == "revoked":
                        revoked = True
                    sources["jiaoziStatusV1"] = {"valid": True, "payload": payload}
                else:
                    # 验签失败按不可信处理(fail-closed 语义留给调用方的
                    # require_trust 通道;此处如实上报原因)
                    sources["jiaoziStatusV1"] = {"valid": False, "reason": result["reason"]}
            except Exception as exc:  # noqa: BLE001 — surface, don't swallow
                sources["jiaoziStatusV1"] = {"error": str(exc)}
        elif etype == "BitstringStatusListEntry":
            try:
                result = check_bitstring_entry(entry, client=client, timeout=timeout)
                sources["bitstringStatusList"] = result
                if result["set"] and result.get("statusPurpose") == "revocation":
                    revoked = True
            except Exception as exc:  # noqa: BLE001
                sources["bitstringStatusList"] = {"error": str(exc)}

    # fail-closed:任一通道判吊销,总口径即 revoked(评估备忘风险 4:
    # 双通道重签节奏不同,窗口内不一致取更严一方)
    if revoked:
        status = "revoked"
    elif status is None:
        status = "unknown"
    return {"revoked": revoked, "status": status, "sources": sources}
