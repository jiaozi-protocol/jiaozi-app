"""SM3 hash (GB/T 32905-2016), pure-stdlib vendored implementation.

国密适配 P0：validator 在 sha256 之外并行输出 SM3 软件基因哈希。
自带实现（约 60 行）而非引第三方依赖：SM3 是确定性哈希，
正确性由 GB/T 32905-2016 附录 A 官方测试向量在单元测试里钉死。
"""

from __future__ import annotations

_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)

_MASK = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _MASK


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _compress(v: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    w = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(16)]
    for j in range(16, 68):
        w.append(
            _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
            ^ _rotl(w[j - 13], 7)
            ^ w[j - 6]
        )
    w2 = [w[j] ^ w[j + 4] for j in range(64)]

    a, b, c, d, e, f, g, h = v
    for j in range(64):
        t = 0x79CC4519 if j < 16 else 0x7A879D8A
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & _MASK, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        if j < 16:
            ff = a ^ b ^ c
            gg = e ^ f ^ g
        else:
            ff = (a & b) | (a & c) | (b & c)
            gg = (e & f) | ((~e & _MASK) & g)
        tt1 = (ff + d + ss2 + w2[j]) & _MASK
        tt2 = (gg + h + ss1 + w[j]) & _MASK
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _p0(tt2)
    return tuple(x ^ y for x, y in zip((a, b, c, d, e, f, g, h), v))


def sm3_digest(data: bytes) -> bytes:
    bit_len = len(data) * 8
    data = data + b"\x80"
    data = data + b"\x00" * ((56 - len(data) % 64) % 64)
    data = data + bit_len.to_bytes(8, "big")

    v = _IV
    for i in range(0, len(data), 64):
        v = _compress(v, data[i : i + 64])
    return b"".join(x.to_bytes(4, "big") for x in v)


def sm3_hex(data: bytes) -> str:
    """Return 'sm3:' + lowercase hex digest, mirroring sha256_hex convention."""
    return "sm3:" + sm3_digest(data).hex()
