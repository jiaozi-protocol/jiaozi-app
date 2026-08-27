"""Jiaozi GDID Python SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .require_trust import (
    DEFAULT_STATUS_SOURCE,
    TRUST_BOUNDARY_HEADER,
    TRUST_STATUS_HEADER,
    TrustDecision,
    TrustPresentation,
    fetch_status_credential,
    presentation_from_headers,
    require_trust,
    trust_deny_http_status,
)
from .status import (
    build_status_payload,
    canonical_json,
    generate_ed25519_keypair,
    is_status_credential_v1,
    sign_status_payload,
    to_standard_ed25519_multibase,
    verify_status_credential,
)
from .vc import (
    VcExportError,
    check_bitstring_entry,
    check_vc_status,
    credential_status_entries,
    decode_status_list_bitstring,
    fetch_vc,
    status_list_bit,
    validate_vc_structure,
)

__all__ = [
    "Gdid",
    # require_trust — credential → permission gate (aligned with gdid-sdk-js)
    "require_trust",
    "trust_deny_http_status",
    "presentation_from_headers",
    "fetch_status_credential",
    "TrustDecision",
    "TrustPresentation",
    "TRUST_STATUS_HEADER",
    "TRUST_BOUNDARY_HEADER",
    "DEFAULT_STATUS_SOURCE",
    # W3C VC export helpers — structure & status layer (#26); full
    # DataIntegrityProof verification needs a generic VC library (see vc.py)
    "fetch_vc",
    "VcExportError",
    "validate_vc_structure",
    "credential_status_entries",
    "decode_status_list_bitstring",
    "status_list_bit",
    "check_bitstring_entry",
    "check_vc_status",
    # jiaozi.status.v1 verification (aligned with gdid-core)
    "verify_status_credential",
    "is_status_credential_v1",
    "build_status_payload",
    "sign_status_payload",
    "generate_ed25519_keypair",
    "to_standard_ed25519_multibase",
    "canonical_json",
    # framework integrations (runtime imports, no hard deps)
    "require_trust_fastapi",
    "require_trust_flask",
]


def __getattr__(name: str) -> Any:
    # Lazy re-export so importing the package never touches fastapi/flask.
    if name in ("require_trust_fastapi", "require_trust_flask"):
        from . import integrations

        return getattr(integrations, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@dataclass
class Gdid:
    base_url: str
    core_url: str | None = None
    api_key: str | None = None
    timeout: float = 30.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self.core_url = (self.core_url or self.base_url).rstrip("/")

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-Jiaozi-Key"] = self.api_key
        return h

    def register(
        self,
        *,
        name: str,
        owner_pubkey: str,
        capabilities: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "name": name,
            "ownerPubkey": owner_pubkey,
            "capabilities": capabilities or [],
        }
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(f"{self.base_url}/api/register", json=payload, headers=self._headers())
        data = r.json()
        if r.status_code >= 400:
            raise RuntimeError(data.get("message") or data.get("error") or r.text)
        return data

    def attest(self, summary: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(f"{self.base_url}/api/verify", json=summary, headers=self._headers())
        data = r.json()
        if r.status_code >= 400:
            raise RuntimeError(data.get("message") or data.get("error") or r.text)
        return data

    def resolve(self, did_or_cert_id: str) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.get(
                f"{self.core_url}/api/resolve",
                params={"q": did_or_cert_id},
            )
        data = r.json()
        if r.status_code >= 400:
            raise RuntimeError(data.get("message") or data.get("error") or r.text)
        return data

    def verify(self, did_or_cert_id: str) -> dict[str, Any]:
        try:
            resolved = self.resolve(did_or_cert_id)
        except Exception as exc:  # noqa: BLE001 — surface as ok:false
            return {
                "ok": False,
                "did": did_or_cert_id,
                "revoked": False,
                "reason": str(exc),
            }
        revoked = (
            resolved.get("revoked") is True
            or resolved.get("status") == "revoked"
            or resolved.get("trustLevel") == "revoked"
        )
        active = (not revoked) and resolved.get("status", "active") == "active"
        return {
            "ok": active,
            "did": resolved.get("did", did_or_cert_id),
            "certId": resolved.get("certId"),
            "trustLevel": resolved.get("trustLevel"),
            "status": resolved.get("status"),
            "revoked": revoked,
            "reason": "revoked" if revoked else None,
            "document": resolved.get("document"),
        }

    def submit_credit(self, events: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] | list[dict[str, Any]]
        if isinstance(events, list):
            payload = {"events": events}
        else:
            payload = events
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(
                f"{self.base_url}/api/credit/events",
                json=payload,
                headers=self._headers(),
            )
        data = r.json()
        if r.status_code >= 400:
            raise RuntimeError(data.get("message") or data.get("error") or r.text)
        return data

    def anchor_credit(
        self,
        *,
        event_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if event_ids is not None:
            body["eventIds"] = event_ids
        if limit is not None:
            body["limit"] = limit
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(
                f"{self.core_url}/api/credit/anchor",
                json=body,
                headers=self._headers(),
            )
        data = r.json()
        if r.status_code >= 400:
            raise RuntimeError(data.get("message") or data.get("error") or r.text)
        return data

    def get_credit_proof(self, event_id: str) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            r = client.get(
                f"{self.core_url}/api/credit/proof",
                params={"eventId": event_id},
            )
        data = r.json()
        if r.status_code >= 400:
            raise RuntimeError(data.get("message") or data.get("error") or r.text)
        return data
