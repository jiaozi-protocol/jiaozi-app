"""Run the official status-v1 test vectors against the Python port.

The vectors (standards/status-v1/test-vectors.json) are the cross-language
contract: the JS implementation generates and passes them, so passing here
proves canonical-JSON byte compatibility and identical failure codes.
"""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jiaozi_gdid.status import verify_status_credential

VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "standards" / "status-v1" / "test-vectors.json"
)


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@unittest.skipUnless(VECTORS_PATH.exists(), "official vectors only exist in the monorepo")
class TestOfficialStatusVectors(unittest.TestCase):
    def test_all_vectors(self) -> None:
        data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], "jiaozi.status.v1")
        for vector in data["vectors"]:
            with self.subTest(vector=vector["name"]):
                kwargs = {}
                opts = vector.get("verifyOptions", {})
                if "expectedIssuer" in opts:
                    kwargs["expected_issuer"] = opts["expectedIssuer"]
                if "trustedKeys" in opts:
                    kwargs["trusted_keys"] = opts["trustedKeys"]
                if "minSerial" in opts:
                    kwargs["min_serial"] = opts["minSerial"]
                if "minSerialDelta" in opts:
                    kwargs["min_serial"] = (
                        vector["credential"]["payload"]["serial"] + opts["minSerialDelta"]
                    )
                verify_at = vector.get("verifyAt", "2026-08-08T00:00:30.000Z")
                result = verify_status_credential(
                    vector["credential"], now=_parse_iso(verify_at), **kwargs
                )
                expect = vector["expect"]
                self.assertEqual(bool(result["valid"]), bool(expect["valid"]), result)
                if not expect["valid"]:
                    self.assertEqual(result.get("reason"), expect.get("reason"), result)


if __name__ == "__main__":
    unittest.main()
