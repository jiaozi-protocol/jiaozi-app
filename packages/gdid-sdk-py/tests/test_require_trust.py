"""Port of gdid-sdk-js require-trust.test.ts — same scenarios, same expectations."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from jiaozi_gdid import (
    DEFAULT_STATUS_SOURCE,
    TrustPresentation,
    build_status_payload,
    fetch_status_credential,
    generate_ed25519_keypair,
    presentation_from_headers,
    require_trust,
    sign_status_payload,
    to_standard_ed25519_multibase,
    trust_deny_http_status,
)

issuer = generate_ed25519_keypair()

_UNSET = object()


def mint_credential(
    *,
    trust_level: object = _UNSET,
    status: str = "active",
    ttl_seconds: int = 300,
    now: datetime | None = None,
) -> dict:
    payload = build_status_payload(
        cert_id="JIAOZI-2026-000042",
        did="did:web:core.jiaozi.io:agents:JIAOZI-2026-000042",
        status=status,
        trust_level="software" if trust_level is _UNSET else trust_level,  # type: ignore[arg-type]
        issuer="test-issuer",
        ttl_seconds=ttl_seconds,
        now=now,
    )
    return sign_status_payload(
        payload, issuer["privateKeyPkcs8Base64"], issuer["publicKeyMultibase"]
    )


class TestRequireTrustPureChecker:
    def test_allows_valid_active_credential_at_default_min_level(self):
        check = require_trust()
        d = check({"statusCredential": mint_credential()})
        assert d.allowed is True
        assert d.trust_level == "software"
        assert d.cert_id == "JIAOZI-2026-000042"

    def test_denies_when_no_credential_presented(self):
        check = require_trust()
        for d in [check(), check(None), check({}), check(TrustPresentation())]:
            assert d.allowed is False
            assert d.reason_code == "no_credential"
            assert "未出示" in d.reason
            assert "No status credential" in d.reason

    def test_denies_expired_credential(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        check = require_trust()
        d = check({"statusCredential": mint_credential(ttl_seconds=60, now=past)})
        assert d.allowed is False
        assert d.reason_code == "expired"
        assert "过期" in d.reason

    def test_denies_revoked_credential_even_if_fresh(self):
        check = require_trust()
        d = check({"statusCredential": mint_credential(status="revoked", trust_level="revoked")})
        assert d.allowed is False
        assert d.reason_code == "revoked"
        assert "吊销" in d.reason
        assert d.cert_id == "JIAOZI-2026-000042"

    def test_denies_suspended_credential(self):
        check = require_trust()
        d = check({"statusCredential": mint_credential(status="suspended")})
        assert d.allowed is False
        assert d.reason_code == "suspended"

    def test_fails_closed_on_unknown_live_status(self):
        check = require_trust()
        d = check({"statusCredential": mint_credential(status="unknown")})
        assert d.allowed is False
        assert d.reason_code == "invalid_credential"

    def test_denies_tampered_credential(self):
        cred = mint_credential()
        tampered = {**cred, "payload": {**cred["payload"], "trustLevel": "tpm"}}
        check = require_trust()
        d = check({"statusCredential": tampered})
        assert d.allowed is False
        assert d.reason_code == "invalid_credential"
        assert "bad_signature" in d.reason

    def test_denies_below_min_level_bronze_silver_gold(self):
        silver_gate = require_trust(min_level="cloud_attest")
        bronze = silver_gate({"statusCredential": mint_credential(trust_level="software")})
        assert bronze.allowed is False
        assert bronze.reason_code == "insufficient_level"
        assert "等级不足" in bronze.reason

        silver = silver_gate({"statusCredential": mint_credential(trust_level="cloud_attest")})
        assert silver.allowed is True

        gold_gate = require_trust(min_level="tee")
        assert (
            gold_gate({"statusCredential": mint_credential(trust_level="cloud_attest")}).allowed
            is False
        )
        # tee and tpm are both gold — either satisfies a gold gate
        assert gold_gate({"statusCredential": mint_credential(trust_level="tpm")}).allowed is True
        assert gold_gate({"statusCredential": mint_credential(trust_level="tee")}).allowed is True

    def test_treats_null_trust_level_as_below_any_gate(self):
        check = require_trust()
        d = check({"statusCredential": mint_credential(trust_level=None)})
        assert d.allowed is False
        assert d.reason_code == "insufficient_level"

    def test_denies_behaviours_outside_declared_boundary(self):
        write_gate = require_trust(behaviors=["write"])
        d = write_gate(
            {
                "statusCredential": mint_credential(),
                "behaviorBoundary": {"permissions": ["read"]},
            }
        )
        assert d.allowed is False
        assert d.reason_code == "behavior_out_of_boundary"
        assert "越界:write" in d.reason

    def test_allows_behaviours_inside_boundary_or_when_none_declared(self):
        write_gate = require_trust(behaviors=["write"])
        inside = write_gate(
            {
                "statusCredential": mint_credential(),
                "behaviorBoundary": {"permissions": ["read", "write"]},
            }
        )
        assert inside.allowed is True
        undeclared = write_gate({"statusCredential": mint_credential()})
        assert undeclared.allowed is True

    def test_honours_verify_passthrough_trusted_keys_pinning(self):
        check = require_trust(verify={"trusted_keys": ["z-not-this-key"]})
        d = check({"statusCredential": mint_credential()})
        assert d.allowed is False
        assert "untrusted_key" in d.reason


class TestVerifyPolicies:
    """分级验证策略 online/pinned/offline."""

    pinned_standard = to_standard_ed25519_multibase(issuer["publicKeyMultibase"])

    def test_defaults_to_online_and_marks_freshness_verified(self):
        d = require_trust()({"statusCredential": mint_credential()})
        assert d.allowed is True
        assert d.freshness == "verified"

    def test_never_downgrades_unless_offline_chosen(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        expired = mint_credential(ttl_seconds=60, now=past)
        for check in [
            require_trust(),
            require_trust(policy="online"),
            require_trust(policy="pinned", issuer_keys=[self.pinned_standard]),
        ]:
            d = check({"statusCredential": expired})
            assert d.allowed is False
            assert d.reason_code == "expired"

    def test_pinned_verifies_locally_against_pinned_issuer_key_either_form(self):
        for key in [self.pinned_standard, issuer["publicKeyMultibase"]]:
            check = require_trust(policy="pinned", issuer_keys=[key])
            d = check({"statusCredential": mint_credential()})
            assert d.allowed is True
            assert d.freshness == "verified"

    def test_pinned_rejects_credential_whose_embedded_key_matches_no_pin(self):
        stranger = generate_ed25519_keypair()
        check = require_trust(
            policy="pinned",
            issuer_keys=[to_standard_ed25519_multibase(stranger["publicKeyMultibase"])],
        )
        d = check({"statusCredential": mint_credential()})
        assert d.allowed is False
        assert d.reason_code == "invalid_credential"
        assert "pinned_key_mismatch" in d.reason

    def test_pinned_and_offline_refuse_to_build_without_issuer_keys(self):
        with pytest.raises(ValueError, match="issuerKeys"):
            require_trust(policy="pinned")
        with pytest.raises(ValueError, match="issuerKeys"):
            require_trust(policy="offline", issuer_keys=[])

    def test_offline_verifies_signature_locally_and_marks_freshness_unverified(self):
        check = require_trust(policy="offline", issuer_keys=[self.pinned_standard])
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        # 过期凭证在 offline 下仍可通过,但结果显式标注新鲜度未验证
        for cred in [mint_credential(), mint_credential(ttl_seconds=60, now=past)]:
            d = check({"statusCredential": cred})
            assert d.allowed is True
            assert d.freshness == "unverified"

    def test_offline_still_denies_revoked_key_mismatched_and_tampered(self):
        check = require_trust(policy="offline", issuer_keys=[self.pinned_standard])

        revoked = check(
            {"statusCredential": mint_credential(status="revoked", trust_level="revoked")}
        )
        assert revoked.allowed is False
        assert revoked.reason_code == "revoked"

        stranger = generate_ed25519_keypair()
        stranger_cred = sign_status_payload(
            mint_credential()["payload"],
            stranger["privateKeyPkcs8Base64"],
            stranger["publicKeyMultibase"],
        )
        mismatch = check({"statusCredential": stranger_cred})
        assert mismatch.allowed is False
        assert "pinned_key_mismatch" in mismatch.reason

        cred = mint_credential()
        tampered = {**cred, "payload": {**cred["payload"], "trustLevel": "tpm"}}
        bad = check({"statusCredential": tampered})
        assert bad.allowed is False
        assert "bad_signature" in bad.reason


class TestFetchStatusCredential:
    def test_gets_credential_from_default_or_configured_status_source(self):
        cred = mint_credential()
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, json=cred)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        from_default = fetch_status_credential("JIAOZI-2026-000042", client=client)
        assert from_default == cred
        assert calls[0] == f"{DEFAULT_STATUS_SOURCE}/api/status/JIAOZI-2026-000042"

        fetch_status_credential(
            "JIAOZI-2026-000042",
            status_source="https://mirror.jiaozi.tech/",
            client=client,
        )
        assert calls[1] == "https://mirror.jiaozi.tech/api/status/JIAOZI-2026-000042"


class TestPresentationFromHeaders:
    def test_parses_raw_json_and_base64_headers(self):
        cred = mint_credential()
        boundary = {"permissions": ["read"]}
        from_raw = presentation_from_headers(
            {
                "x-jiaozi-status": json.dumps(cred),
                "x-jiaozi-boundary": json.dumps(boundary),
            }
        )
        assert from_raw.status_credential == cred
        assert from_raw.behavior_boundary == boundary

        b64url = base64.urlsafe_b64encode(json.dumps(cred).encode("utf-8")).rstrip(b"=")
        from_b64 = presentation_from_headers({"x-jiaozi-status": b64url.decode("ascii")})
        assert from_b64.status_credential == cred

    def test_yields_no_credential_for_absent_or_garbled_headers(self):
        assert presentation_from_headers({}).status_credential is None
        assert (
            presentation_from_headers({"x-jiaozi-status": "not json at all"}).status_credential
            is None
        )


class TestFlaskIntegration:
    """Counterpart of the JS requireTrustExpress tests."""

    @staticmethod
    def make_app(**options):
        flask = pytest.importorskip("flask")
        from jiaozi_gdid import require_trust_flask

        app = flask.Flask(__name__)

        @app.post("/api/write")
        @require_trust_flask(**options)
        def write():
            return {"ok": True, "caller": flask.g.jiaozi_trust.to_dict()}

        return app

    def test_calls_view_and_attaches_decision_on_allow(self):
        app = self.make_app(min_level="software")
        client = app.test_client()
        r = client.post(
            "/api/write", headers={"x-jiaozi-status": json.dumps(mint_credential())}
        )
        assert r.status_code == 200
        assert r.get_json()["ok"] is True
        assert r.get_json()["caller"]["allowed"] is True

    def test_responds_401_with_reason_when_no_credential(self):
        app = self.make_app()
        r = app.test_client().post("/api/write")
        assert r.status_code == 401
        assert r.get_json()["error"] == "no_credential"

    def test_responds_403_with_reason_on_insufficient_level(self):
        app = self.make_app(min_level="tee")
        r = app.test_client().post(
            "/api/write",
            headers={"x-jiaozi-status": json.dumps(mint_credential(trust_level="software"))},
        )
        assert r.status_code == 403
        assert r.get_json()["error"] == "insufficient_level"


class TestFastApiIntegration:
    @staticmethod
    def make_client(**options):
        pytest.importorskip("fastapi")
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from jiaozi_gdid import require_trust_fastapi

        app = FastAPI()
        gate = require_trust_fastapi(**options)

        @app.post("/api/write")
        def write(trust=Depends(gate)):
            return {"ok": True, "caller": trust.to_dict()}

        return TestClient(app)

    def test_allows_and_exposes_decision(self):
        client = self.make_client(min_level="software")
        r = client.post(
            "/api/write", headers={"x-jiaozi-status": json.dumps(mint_credential())}
        )
        assert r.status_code == 200
        assert r.json()["caller"]["allowed"] is True

    def test_responds_401_when_no_credential(self):
        client = self.make_client()
        r = client.post("/api/write")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "no_credential"

    def test_responds_403_on_insufficient_level(self):
        client = self.make_client(min_level="tee")
        r = client.post(
            "/api/write",
            headers={"x-jiaozi-status": json.dumps(mint_credential(trust_level="software"))},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_level"


class TestTrustDenyHttpStatus:
    def test_maps_no_credential_to_401_everything_else_403(self):
        assert trust_deny_http_status("no_credential") == 401
        for code in [
            "invalid_credential",
            "expired",
            "revoked",
            "suspended",
            "insufficient_level",
            "behavior_out_of_boundary",
        ]:
            assert trust_deny_http_status(code) == 403
