"""attest.v1 delegation 扩展容器(结构预留位,R3 签字 2026-08-25)行为锁定。

与 JS 侧 gdid-core/src/attest-delegation.test.ts 同一组语义:
① 带 delegation 对象的摘要正常构造/序列化并保留进 API 载荷;
② 不带该字段时行为与之前完全一致(键不出现);
③ delegation 为非对象时拒绝(ValueError)。
语义对齐 standards/delegation-v1/DESIGN.md §4.2 / §6.3 / §6.4。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jiaozi_validator.scan import build_summary, payload_for_api

OWNER = "z6MkDemoOwnerKey"

DELEGATION = {
    # 子字段草案(delegation-v1 DESIGN §4.2):运行时不校验,不透明透传
    "delegator": "JIAOZI-2026-000123",
    "grantedCapabilities": ["procure", "pay"],
    "caveats": [{"type": "maxAmountPerTx", "currency": "CNY", "value": 10000}],
    "expiresAt": "2026-09-01T00:00:00.000Z",
}


def _build(tmp_path: Path, **kwargs):
    return build_summary(
        agent_name="DemoAgent",
        target=tmp_path,
        owner_pubkey=OWNER,
        **kwargs,
    )


def test_delegation_object_is_carried_opaquely(tmp_path: Path) -> None:
    summary = _build(tmp_path, delegation=DELEGATION)
    assert summary["delegation"] == DELEGATION
    # 进入跨境 API 载荷(整体签名域),且 JSON 序列化可往返
    api_body = payload_for_api(summary)
    assert api_body["delegation"] == DELEGATION
    assert json.loads(json.dumps(api_body))["delegation"] == DELEGATION


def test_empty_delegation_object_is_accepted(tmp_path: Path) -> None:
    summary = _build(tmp_path, delegation={})
    assert summary["delegation"] == {}


def test_absent_delegation_keeps_legacy_shape(tmp_path: Path) -> None:
    summary = _build(tmp_path)
    assert "delegation" not in summary
    assert "delegation" not in payload_for_api(summary)
    # 与带 delegation 的摘要相比,其余字段集合完全一致
    with_delegation = _build(tmp_path, delegation=DELEGATION)
    assert set(with_delegation) - set(summary) == {"delegation"}


@pytest.mark.parametrize("bad", ["delegated", 42, ["JIAOZI-2026-000123"]])
def test_non_object_delegation_is_rejected(tmp_path: Path, bad) -> None:
    with pytest.raises(ValueError, match="delegation"):
        _build(tmp_path, delegation=bad)
