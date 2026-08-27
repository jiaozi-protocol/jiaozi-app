"""C12④ 修复验收：主人公钥来源纪律（无钥硬拒绝 / --demo-owner-key 显式放行 / 真实钥零变化）。"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from jiaozi_validator.cli import main
from jiaozi_validator.scan import (
    DEMO_OWNER_PUBKEY,
    OwnerKeyError,
    load_owner_pubkey,
    payload_for_api,
)

API_CONTRACT_KEYS = {
    "schema",
    "agentName",
    "softwareGeneHash",
    "softwareGeneHashSm3",
    "checks",
    "score",
    "trustLevel",
    "ownerPubkey",
    "timestamp",
    "clientNonce",
    "behaviorBoundary",
}


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestLoadOwnerPubkey(unittest.TestCase):
    def test_no_path_no_demo_raises(self) -> None:
        with self.assertRaises(OwnerKeyError):
            load_owner_pubkey(None)

    def test_no_path_demo_allowed_returns_placeholder(self) -> None:
        self.assertEqual(load_owner_pubkey(None, allow_demo=True), DEMO_OWNER_PUBKEY)

    def test_missing_file_raises_even_with_demo(self) -> None:
        with self.assertRaises(OwnerKeyError):
            load_owner_pubkey(Path("does-not-exist.pub"), allow_demo=True)

    def test_real_file_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pub = Path(tmp) / "owner.pub"
            pub.write_text("zRealKey123\n", encoding="utf-8")
            self.assertEqual(load_owner_pubkey(pub), "zRealKey123")

    def test_empty_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pub = Path(tmp) / "owner.pub"
            pub.write_text("  \n", encoding="utf-8")
            with self.assertRaises(OwnerKeyError):
                load_owner_pubkey(pub)


class TestCliOwnerKeyDiscipline(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agent_dir = Path(self._tmp.name) / "agent"
        self.agent_dir.mkdir()
        (self.agent_dir / "agent.md").write_text("# demo agent\n", encoding="utf-8")

    def test_no_key_no_flag_rejects(self) -> None:
        code, out, err = run_cli(["--path", str(self.agent_dir), "--dry-run"])
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")  # no summary is produced
        self.assertIn("未提供主人公钥", err)
        self.assertIn("no owner public key provided", err)
        self.assertIn("--demo-owner-key", err)
        self.assertIn("gen-owner-key.mjs", err)

    def test_demo_flag_allows_with_warning_and_marker(self) -> None:
        code, out, err = run_cli(
            ["--path", str(self.agent_dir), "--demo-owner-key", "--dry-run"]
        )
        self.assertEqual(code, 0)
        self.assertIn("WARNING", err)
        self.assertIn("占位主人公钥", err)
        summary = json.loads(out)
        self.assertEqual(summary["ownerPubkey"], DEMO_OWNER_PUBKEY)
        self.assertIs(summary["_local"]["ownerKeyDemo"], True)
        # The marker must never reach the API payload (contract unchanged).
        api_body = payload_for_api(summary)
        self.assertNotIn("_local", api_body)
        self.assertNotIn("ownerKeyDemo", api_body)
        self.assertTrue(set(api_body).issubset(API_CONTRACT_KEYS))

    def test_real_key_unchanged_behavior(self) -> None:
        pub = Path(self._tmp.name) / "owner.pub"
        pub.write_text("zRealOwnerKeyForTest\n", encoding="utf-8")
        code, out, err = run_cli(
            [
                "--path",
                str(self.agent_dir),
                "--owner-pubkey-file",
                str(pub),
                "--dry-run",
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")  # no warning, nothing on stderr
        summary = json.loads(out)
        self.assertEqual(summary["ownerPubkey"], "zRealOwnerKeyForTest")
        self.assertNotIn("ownerKeyDemo", summary["_local"])
        self.assertTrue(set(payload_for_api(summary)).issubset(API_CONTRACT_KEYS))

    def test_real_key_file_beats_demo_flag(self) -> None:
        pub = Path(self._tmp.name) / "owner.pub"
        pub.write_text("zRealOwnerKeyForTest\n", encoding="utf-8")
        code, out, err = run_cli(
            [
                "--path",
                str(self.agent_dir),
                "--owner-pubkey-file",
                str(pub),
                "--demo-owner-key",
                "--dry-run",
            ]
        )
        self.assertEqual(code, 0)
        summary = json.loads(out)
        self.assertEqual(summary["ownerPubkey"], "zRealOwnerKeyForTest")
        self.assertNotIn("ownerKeyDemo", summary["_local"])

    def test_missing_key_file_rejects(self) -> None:
        code, out, err = run_cli(
            [
                "--path",
                str(self.agent_dir),
                "--owner-pubkey-file",
                str(Path(self._tmp.name) / "nope.pub"),
                "--dry-run",
            ]
        )
        self.assertNotEqual(code, 0)
        self.assertIn("not found", err)


if __name__ == "__main__":
    unittest.main()
