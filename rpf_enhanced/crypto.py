"""RPF7 NG (TFIT) block cipher.

Direct port of CodeWalker / Neodymium's `GTACrypto.DecryptNG` and
`DecryptNGBlock` from `CodeWalker.Core/GameFiles/Utils/GTACrypto.cs`.

Each 16-byte block uses 17 rounds driven by the per-file 272-byte key
(17 x 4 u32 subkeys) and the 17 x 16 x 256 u32 LUT.
"""

from __future__ import annotations

from .jenkhash import jenkins_hash
from .keys import GtaKeys


def get_ng_key_index(name: str, length: int) -> int:
    """Index into the 101-key table, matching `GTACrypto.GetNGKey`."""
    h = _jenkins_lower(name)
    return (h + length + 101 - 40) % 101


def decrypt_ng(data: bytes, keys: GtaKeys, name: str, length: int) -> bytes:
    key_idx = get_ng_key_index(name, length)
    key = keys.ng_keys[key_idx]
    key_u32 = [int.from_bytes(key[i * 4:(i + 1) * 4], "little") for i in range(68)]

    out = bytearray(data)
    n_blocks = len(data) // 16
    for b in range(n_blocks):
        block = bytes(data[b * 16:(b + 1) * 16])
        dec = _decrypt_ng_block(block, key_u32, keys.ng_decrypt_tables)
        out[b * 16:(b + 1) * 16] = dec
    return bytes(out)


def _jenkins_lower(name: str) -> int:
    """Case-folded Jenkins hash — matches CodeWalker's GetNGKey path
    (file names in RPF TOCs are already lower-cased, but be safe)."""
    return jenkins_hash(name.lower().encode("utf-8"))


def _decrypt_ng_block(block: bytes, key_u32: list[int],
                      tables: list[list[list[list[int]]]]) -> bytes:
    sub_keys = [
        (key_u32[4 * i], key_u32[4 * i + 1], key_u32[4 * i + 2], key_u32[4 * i + 3])
        for i in range(17)
    ]

    buf = block
    buf = _round_a(buf, sub_keys[0], tables[0])
    buf = _round_a(buf, sub_keys[1], tables[1])
    for k in range(2, 16):
        buf = _round_b(buf, sub_keys[k], tables[k])
    buf = _round_a(buf, sub_keys[16], tables[16])
    return buf


def _round_a(data: bytes, key: tuple[int, int, int, int],
             table: list[list[int]]) -> bytes:
    x1 = (table[0][data[0]] ^ table[1][data[1]] ^ table[2][data[2]] ^ table[3][data[3]]) ^ key[0]
    x2 = (table[4][data[4]] ^ table[5][data[5]] ^ table[6][data[6]] ^ table[7][data[7]]) ^ key[1]
    x3 = (table[8][data[8]] ^ table[9][data[9]] ^ table[10][data[10]] ^ table[11][data[11]]) ^ key[2]
    x4 = (table[12][data[12]] ^ table[13][data[13]] ^ table[14][data[14]] ^ table[15][data[15]]) ^ key[3]
    return (x1 & 0xFFFFFFFF).to_bytes(4, "little") + \
           (x2 & 0xFFFFFFFF).to_bytes(4, "little") + \
           (x3 & 0xFFFFFFFF).to_bytes(4, "little") + \
           (x4 & 0xFFFFFFFF).to_bytes(4, "little")


def _round_b(data: bytes, key: tuple[int, int, int, int],
             table: list[list[int]]) -> bytes:
    x1 = (table[0][data[0]] ^ table[7][data[7]] ^ table[10][data[10]] ^ table[13][data[13]]) ^ key[0]
    x2 = (table[1][data[1]] ^ table[4][data[4]] ^ table[11][data[11]] ^ table[14][data[14]]) ^ key[1]
    x3 = (table[2][data[2]] ^ table[5][data[5]] ^ table[8][data[8]] ^ table[15][data[15]]) ^ key[2]
    x4 = (table[3][data[3]] ^ table[6][data[6]] ^ table[9][data[9]] ^ table[12][data[12]]) ^ key[3]
    return (x1 & 0xFFFFFFFF).to_bytes(4, "little") + \
           (x2 & 0xFFFFFFFF).to_bytes(4, "little") + \
           (x3 & 0xFFFFFFFF).to_bytes(4, "little") + \
           (x4 & 0xFFFFFFFF).to_bytes(4, "little")
