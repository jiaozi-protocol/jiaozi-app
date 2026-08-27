"""Jiaozi Validator CLI — local health-check → POST /api/verify."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from jiaozi_validator.scan import (
    OwnerKeyError,
    build_summary,
    load_behavior_boundary,
    load_owner_pubkey,
    payload_for_api,
)

_NODE_KEYGEN_ONELINER = (
    "node -e \"const c=require('crypto'),f=require('fs');"
    "const{publicKey,privateKey}=c.generateKeyPairSync('ed25519');"
    "f.writeFileSync('owner.pem',privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});"
    "const d=publicKey.export({type:'spki',format:'der'});"
    "f.writeFileSync('owner.pub','z'+d.subarray(d.length-32).toString('base64url')+'\\n');"
    "console.log('written: owner.pem (private, keep safe) + owner.pub')\""
)

NO_OWNER_KEY_ERROR = f"""\
错误：未提供主人公钥（--owner-pubkey-file）。
凭证的“主人”必须绑定一把真实的公钥，否则任何人都可以声称自己是这个 Agent 的主人。
ERROR: no owner public key provided (--owner-pubkey-file).
A credential must bind a real owner key; otherwise anyone can claim to own this agent.

两条出路 / Two ways forward:

  1) 生成真实密钥并传入 / Generate a real Ed25519 key pair and pass the public key:
       # jiaozi_app 仓库内 / inside the jiaozi_app repo:
       node scripts/gen-owner-key.mjs <name>
       # 或任意装有 Node.js 的机器一行命令 / or a Node.js one-liner anywhere:
       {_NODE_KEYGEN_ONELINER}
       然后 / then:
       jiaozi-validator --owner-pubkey-file owner.pub ...

  2) 仅作演示、明知是占位钥 / Demo only, explicitly accept the public placeholder key:
       jiaozi-validator --demo-owner-key ...
       （输出会带醒目警告，本地报告会带 ownerKeyDemo 标记 /
        output carries a loud warning and the local report is marked ownerKeyDemo）
"""

DEMO_KEY_WARNING = """\
!! 警告：--demo-owner-key 已启用，本次摘要绑定的是【公开的 Demo 占位主人公钥】。
!! 任何人都能使用同一把占位钥——由此签发的凭证不能证明主人身份，仅供演示。
!! WARNING: --demo-owner-key is set. This summary binds the PUBLIC demo placeholder
!! owner key that anyone can claim. A credential issued from it CANNOT prove
!! ownership. Demo use only.\
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jiaozi-validator",
        description="Local Agent health-check → jiaozi.attest.v1 → CN Front",
    )
    parser.add_argument("--agent-name", default="DemoAgent")
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Agent project path to scan (default: cwd)",
    )
    parser.add_argument(
        "--owner-pubkey-file",
        type=Path,
        default=None,
        help=(
            "Owner public key file (e.g. keys/<name>-owner.pub from "
            "scripts/gen-owner-key.mjs). Required unless --demo-owner-key is set."
        ),
    )
    parser.add_argument(
        "--demo-owner-key",
        action="store_true",
        help=(
            "Explicitly use the PUBLIC demo placeholder owner key (demo only; "
            "cannot prove ownership). Prints a warning and marks the local "
            "report with ownerKeyDemo."
        ),
    )
    parser.add_argument(
        "--boundary-file",
        type=Path,
        default=None,
        help="JSON file with behavior boundary: permissions/goals/constraints arrays",
    )
    parser.add_argument("--framework-version", default="mvp-0.1")
    parser.add_argument("--model-id", default="unspecified")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("JIAOZI_VERIFY_URL", "http://127.0.0.1:3000/api/verify"),
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("JIAOZI_API_KEY", "dev-key-change-me"),
        help="Value for X-Jiaozi-Key header",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary JSON only; do not POST",
    )
    args = parser.parse_args(argv)

    if args.owner_pubkey_file is None and not args.demo_owner_key:
        print(NO_OWNER_KEY_ERROR, file=sys.stderr)
        return 2

    try:
        owner = load_owner_pubkey(args.owner_pubkey_file, allow_demo=args.demo_owner_key)
    except OwnerKeyError as exc:
        print(f"jiaozi-validator: {exc}", file=sys.stderr)
        return 2

    owner_key_demo = args.owner_pubkey_file is None
    if owner_key_demo:
        print(DEMO_KEY_WARNING, file=sys.stderr)

    target = args.path.resolve()
    summary = build_summary(
        agent_name=args.agent_name,
        target=target,
        owner_pubkey=owner,
        framework_version=args.framework_version,
        model_id=args.model_id,
        behavior_boundary=load_behavior_boundary(args.boundary_file),
        owner_key_demo=owner_key_demo,
    )
    api_body = payload_for_api(summary)

    if args.dry_run:
        json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0

    headers = {"X-Jiaozi-Key": args.api_key}
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(args.api_url, json=api_body, headers=headers)
    except httpx.HTTPError as exc:
        print(f"POST failed: {exc}", file=sys.stderr)
        return 2

    print(resp.text)
    if resp.status_code >= 400:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
