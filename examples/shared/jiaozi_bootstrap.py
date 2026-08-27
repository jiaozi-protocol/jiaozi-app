"""Shared helpers for framework demos (no framework dependency)."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

# Allow running from examples/* without install
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "gdid-sdk-py" / "src"))

from jiaozi_gdid import Gdid  # noqa: E402


def client() -> Gdid:
    return Gdid(
        base_url=os.environ.get("JIAOZI_BASE_URL", "http://127.0.0.1:3000"),
        core_url=os.environ.get("JIAOZI_CORE_URL", "http://127.0.0.1:3001"),
        api_key=os.environ.get("JIAOZI_API_KEY", "dev-key-change-me"),
    )


def demo_owner_pubkey(label: str = "framework-demo") -> str:
    digest = hashlib.sha256(f"jiaozi-{label}".encode()).hexdigest()[:40]
    return f"zDemo{digest}"


def build_summary(*, agent_name: str, owner_pubkey: str, project_root: Path | None = None) -> dict:
    root = project_root or Path(__file__).resolve().parent
    material = f"{agent_name}:{owner_pubkey}:{root}".encode()
    gene = "sha256:" + hashlib.sha256(material).hexdigest()
    return {
        "schema": "jiaozi.attest.v1",
        "agentName": agent_name,
        "softwareGeneHash": gene,
        "checks": {"maliciousApi": "pass", "secretLeak": "pass"},
        "score": 95,
        "trustLevel": "software",
        "ownerPubkey": owner_pubkey,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "clientNonce": uuid4().hex,
    }


def bootstrap_agent(agent_name: str, capabilities: list[str] | None = None) -> dict:
    """register + attest → identity bundle for framework runtime."""
    gdid = client()
    owner = demo_owner_pubkey(agent_name)
    reg = gdid.register(name=agent_name, owner_pubkey=owner, capabilities=capabilities or ["demo"])
    issued = gdid.attest(build_summary(agent_name=agent_name, owner_pubkey=owner))
    return {
        "agentName": agent_name,
        "ownerPubkey": owner,
        "agentId": reg.get("agentId"),
        "registrationDid": reg.get("did"),
        "certId": issued["certId"],
        "did": issued["did"],
        "trustLevel": issued.get("trustLevel"),
    }


def require_verified(did_or_cert: str, min_trust: str = "software") -> dict:
    """Gate: peer must resolve and not be revoked."""
    order = ["software", "cloud_attest", "tee", "tpm"]
    result = client().verify(did_or_cert)
    if not result.get("ok"):
        raise PermissionError(f"GDID verify failed: {result.get('reason') or result}")
    trust = result.get("trustLevel") or "software"
    if trust == "revoked" or result.get("revoked"):
        raise PermissionError("GDID revoked")
    if order.index(trust) < order.index(min_trust):
        raise PermissionError(f"trustLevel {trust} < required {min_trust}")
    return result
