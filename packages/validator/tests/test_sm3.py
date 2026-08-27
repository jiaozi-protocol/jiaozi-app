"""GB/T 32905-2016 附录 A 官方测试向量 + 边界用例。"""

import unittest

from jiaozi_validator.sm3 import sm3_digest, sm3_hex


class TestSm3(unittest.TestCase):
    def test_official_vector_abc(self) -> None:
        # GB/T 32905-2016 A.1
        self.assertEqual(
            sm3_digest(b"abc").hex(),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        )

    def test_official_vector_512bit(self) -> None:
        # GB/T 32905-2016 A.2: "abcd" * 16 (512 bits)
        self.assertEqual(
            sm3_digest(b"abcd" * 16).hex(),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        )

    def test_empty_input(self) -> None:
        self.assertEqual(
            sm3_digest(b"").hex(),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        )

    def test_prefix_convention(self) -> None:
        self.assertTrue(sm3_hex(b"abc").startswith("sm3:"))
        self.assertEqual(len(sm3_hex(b"abc")), 4 + 64)


if __name__ == "__main__":
    unittest.main()
