"""LangChain tool: verify peer Agent via Jiaozi GDID."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "shared"))
sys.path.insert(0, str(ROOT / "packages" / "gdid-sdk-py" / "src"))

from jiaozi_bootstrap import require_verified  # noqa: E402


def jiaozi_verify_peer(did_or_cert_id: str) -> str:
    """Verify a peer AI Agent certificate / DID before collaboration."""
    result = require_verified(did_or_cert_id)
    return json.dumps(
        {
            "ok": True,
            "certId": result.get("certId"),
            "did": result.get("did"),
            "trustLevel": result.get("trustLevel"),
        },
        ensure_ascii=False,
    )


# Optional LangChain StructuredTool factory
def as_langchain_tool():
    try:
        from langchain_core.tools import StructuredTool
        from pydantic import BaseModel, Field
    except ImportError as exc:  # pragma: no cover
        raise ImportError("pip install langchain-core pydantic") from exc

    class Input(BaseModel):
        did_or_cert_id: str = Field(..., description="Peer JIAOZI-… (legacy JP-…) or did:web:…")

    return StructuredTool.from_function(
        func=lambda did_or_cert_id: jiaozi_verify_peer(did_or_cert_id),
        name="jiaozi_verify_peer",
        description="Verify peer Agent GDID certificate before trusting them.",
        args_schema=Input,
    )
