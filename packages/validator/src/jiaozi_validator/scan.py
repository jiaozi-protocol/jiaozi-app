"""Local Agent health-check helpers (no source leaves the machine)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .sm3 import sm3_hex

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"][^'\"]{8,}"),
    re.compile(r"(?i)sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"(?i)-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"),
]

RISKY_API_HINTS = [
    "eval(",
    "exec(",
    "subprocess.Popen",
    "os.system(",
    "child_process",
]

# Public, deterministic placeholder — anyone can claim it, so it must never be
# used silently (see OwnerKeyError / --demo-owner-key).
DEMO_OWNER_PUBKEY = (
    "zDemoOwnerPubkey" + hashlib.sha256(b"jiaozi-mvp-demo").hexdigest()[:32]
)


class OwnerKeyError(ValueError):
    """Raised when an owner public key cannot be resolved safely."""


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_path_tree(root: Path) -> str:
    """Hash relative paths + file contents (config-oriented files only)."""
    if not root.exists():
        return sha256_hex(b"missing:" + str(root).encode())

    if root.is_file():
        return sha256_hex(root.read_bytes())

    parts: list[bytes] = []
    patterns = ("*.json", "*.yaml", "*.yml", "*.toml", "*.env.example", "*.md", "*.py", "*.ts", "*.js")
    files: list[Path] = []
    for pat in patterns:
        files.extend(root.rglob(pat))
    for path in sorted({p for p in files if p.is_file()}, key=lambda p: str(p).lower()):
        rel = path.relative_to(root).as_posix().encode()
        parts.append(rel + b"\0" + path.read_bytes())
    if not parts:
        parts.append(b"empty-tree")
    return sha256_hex(b"\n".join(parts))


def scan_secret_leak(root: Path) -> str:
    if not root.exists():
        return "skip"
    paths = list(root.rglob("*")) if root.is_dir() else [root]
    for path in paths:
        if not path.is_file() or path.suffix in {".png", ".jpg", ".webp", ".gif"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                return "fail"
    return "pass"


def scan_malicious_api(root: Path) -> str:
    if not root.exists():
        return "skip"
    paths = list(root.rglob("*")) if root.is_dir() else [root]
    hit = False
    for path in paths:
        if not path.is_file() or path.suffix not in {".py", ".js", ".ts", ".mjs", ".cjs"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for hint in RISKY_API_HINTS:
            if hint in text:
                hit = True
                break
    # Heuristic warning only: presence marks fail for MVP demo strictness
    return "fail" if hit else "pass"


def _gene_material(
    *,
    model_hash: str,
    prompt_hash: str,
    framework_version: str,
    owner_pubkey: str,
) -> bytes:
    return "||".join([model_hash, prompt_hash, framework_version, owner_pubkey]).encode()


def software_gene_hash(
    *,
    model_hash: str,
    prompt_hash: str,
    framework_version: str,
    owner_pubkey: str,
) -> str:
    return sha256_hex(_gene_material(
        model_hash=model_hash,
        prompt_hash=prompt_hash,
        framework_version=framework_version,
        owner_pubkey=owner_pubkey,
    ))


def software_gene_hash_sm3(
    *,
    model_hash: str,
    prompt_hash: str,
    framework_version: str,
    owner_pubkey: str,
) -> str:
    """国密并行摘要：同一份基因材料的 SM3 哈希（GB/T 32905-2016）。

    sha256 仍是去重与国际互操作的主摘要；SM3 供境内验证方按国密口径复核。
    """
    return sm3_hex(_gene_material(
        model_hash=model_hash,
        prompt_hash=prompt_hash,
        framework_version=framework_version,
        owner_pubkey=owner_pubkey,
    ))


def score_from_checks(checks: dict[str, str]) -> int:
    score = 100
    for result in checks.values():
        if result == "fail":
            score -= 40
        elif result == "skip":
            score -= 10
    return max(0, min(100, score))


def load_behavior_boundary(path: Path | None) -> dict[str, Any] | None:
    """行为边界（GB/Z 185.3 对齐）：主人自述的权限/目标/约束，JSON 文件提供。"""
    if not path:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"permissions", "goals", "constraints"}
    boundary = {k: v for k, v in data.items() if k in allowed and isinstance(v, list)}
    return boundary or None


def build_summary(
    *,
    agent_name: str,
    target: Path,
    owner_pubkey: str,
    framework_version: str = "unknown",
    model_id: str = "unspecified",
    behavior_boundary: dict[str, Any] | None = None,
    delegation: dict[str, Any] | None = None,
    owner_key_demo: bool = False,
) -> dict[str, Any]:
    """构造 jiaozi.attest.v1 摘要。

    `delegation` 为委托扩展容器(结构预留位,R3 签字 2026-08-25):可选、
    不透明对象——出现时仅做"是 dict"的形状校验,不校验内部结构。初始已知
    子字段(仅文档层面登记,语义对齐 standards/delegation-v1/DESIGN.md
    §4.2/§6.3):`delegator`(委托方标识)与 scope 收缩相关字段
    (`grantedCapabilities` / `caveats` / `expiresAt`)。
    """
    if delegation is not None and not isinstance(delegation, dict):
        raise ValueError(
            "delegation 必须是对象(dict)或缺席 / "
            "delegation must be a JSON object (dict) or absent"
        )
    from datetime import datetime, timezone
    from uuid import uuid4

    tree_hash = hash_path_tree(target)
    model_hash = sha256_hex(model_id.encode())
    prompt_hash = tree_hash
    checks = {
        "maliciousApi": scan_malicious_api(target),
        "secretLeak": scan_secret_leak(target),
    }
    return {
        **({"behaviorBoundary": behavior_boundary} if behavior_boundary else {}),
        **({"delegation": delegation} if delegation is not None else {}),
        "schema": "jiaozi.attest.v1",
        "agentName": agent_name,
        "softwareGeneHash": software_gene_hash(
            model_hash=model_hash,
            prompt_hash=prompt_hash,
            framework_version=framework_version,
            owner_pubkey=owner_pubkey,
        ),
        "softwareGeneHashSm3": software_gene_hash_sm3(
            model_hash=model_hash,
            prompt_hash=prompt_hash,
            framework_version=framework_version,
            owner_pubkey=owner_pubkey,
        ),
        "checks": checks,
        "score": score_from_checks(checks),
        "trustLevel": "software",
        "ownerPubkey": owner_pubkey,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "clientNonce": uuid4().hex,
        # local-only debug (stripped before POST)
        "_local": {
            "target": str(target),
            "treeHash": tree_hash,
            "modelId": model_id,
            "frameworkVersion": framework_version,
            # ownerKeyDemo lives here (not in the API contract fields) so it
            # can never leak into the submitted payload.
            **({"ownerKeyDemo": True} if owner_key_demo else {}),
        },
    }


def payload_for_api(summary: dict[str, Any]) -> dict[str, Any]:
    """Strip local-only fields before cross-border / API submit."""
    return {k: v for k, v in summary.items() if not k.startswith("_")}


def load_owner_pubkey(path: Path | None, *, allow_demo: bool = False) -> str:
    """Resolve the owner public key.

    A real key file always wins. Without one, the public demo placeholder is
    only returned when explicitly opted in (allow_demo) — never silently, as a
    credential bound to it cannot prove ownership.
    """
    if path is not None:
        if not path.is_file():
            raise OwnerKeyError(
                f"主人公钥文件不存在 / owner pubkey file not found: {path}"
            )
        key = path.read_text(encoding="utf-8").strip()
        if not key:
            raise OwnerKeyError(
                f"主人公钥文件为空 / owner pubkey file is empty: {path}"
            )
        return key
    if allow_demo:
        return DEMO_OWNER_PUBKEY
    raise OwnerKeyError(
        "未提供主人公钥且未显式允许 Demo 占位钥 / "
        "no owner pubkey provided and demo placeholder not explicitly allowed"
    )
