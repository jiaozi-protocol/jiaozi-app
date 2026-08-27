"""Framework glue for require_trust — FastAPI dependency & Flask decorator.

Frameworks are NOT hard dependencies of this package: fastapi / flask are
imported at call time only (install them yourself, e.g.
`pip install fastapi` / `pip install flask`).

Deny responses mirror the JS requireTrustExpress body:
{"error": reasonCode, "reason": …, "trustLevel": …, "certId"?: …} with
HTTP 401 (no_credential) / 403 (everything else).
"""

# NOTE: no `from __future__ import annotations` here — the FastAPI dependency's
# `request: Request` annotation must stay a real class (evaluated at def time,
# when Request is in the closure's scope), or FastAPI can't resolve it.
import functools
from typing import Any, Callable

from .require_trust import (
    TrustDecision,
    presentation_from_headers,
    require_trust,
    trust_deny_http_status,
)


def _deny_body(decision: TrustDecision) -> dict[str, Any]:
    body: dict[str, Any] = {
        "error": decision.reason_code,
        "reason": decision.reason,
        "trustLevel": decision.trust_level,
    }
    if decision.cert_id:
        body["certId"] = decision.cert_id
    return body


def require_trust_fastapi(**options: Any) -> Callable[..., TrustDecision]:
    """FastAPI dependency factory (Depends style). On deny, raises
    HTTPException 401/403 with the bilingual reason; on allow, returns the
    TrustDecision so the endpoint can inspect trust_level / payload.

    Usage::

        from fastapi import Depends, FastAPI
        from jiaozi_gdid import require_trust_fastapi

        app = FastAPI()
        write_gate = require_trust_fastapi(min_level="cloud_attest", behaviors=["write"])

        @app.post("/api/write")
        def write(trust = Depends(write_gate)):
            return {"ok": True, "caller": trust.to_dict()}
    """
    from fastapi import HTTPException, Request  # runtime import — optional dep

    check = require_trust(**options)

    def dependency(request: Request) -> TrustDecision:
        decision = check(presentation_from_headers(dict(request.headers)))
        if not decision.allowed:
            raise HTTPException(
                status_code=trust_deny_http_status(decision.reason_code),
                detail=_deny_body(decision),
            )
        return decision

    return dependency


def require_trust_flask(**options: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Flask view decorator. On deny, answers 401/403 with the bilingual
    reason itself; on allow, stores the decision on `flask.g.jiaozi_trust`
    and calls the view.

    Usage::

        from flask import Flask, g
        from jiaozi_gdid import require_trust_flask

        app = Flask(__name__)

        @app.post("/api/write")
        @require_trust_flask(min_level="cloud_attest", behaviors=["write"])
        def write():
            return {"ok": True, "caller": g.jiaozi_trust.to_dict()}
    """
    check = require_trust(**options)

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from flask import g, jsonify, request  # runtime import — optional dep

            decision = check(presentation_from_headers(dict(request.headers)))
            g.jiaozi_trust = decision
            if not decision.allowed:
                return (
                    jsonify(_deny_body(decision)),
                    trust_deny_http_status(decision.reason_code),
                )
            return view(*args, **kwargs)

        return wrapper

    return decorator
