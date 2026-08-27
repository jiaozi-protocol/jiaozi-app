"""CrewAI tool — gate collaboration on Jiaozi GDID verify."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "examples" / "shared"))

from jiaozi_bootstrap import require_verified  # noqa: E402


def verify_peer_cert(did_or_cert_id: str) -> str:
    """Verify peer Agent GDID before assigning tasks."""
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


def as_crewai_tool():
    try:
        from crewai.tools import tool
    except ImportError as exc:  # pragma: no cover
        raise ImportError("pip install crewai") from exc

    @tool("jiaozi_verify_peer")
    def _tool(did_or_cert_id: str) -> str:
        """Verify a peer AI Agent certificate or DID via Jiaozi GDID."""
        return verify_peer_cert(did_or_cert_id)

    return _tool
