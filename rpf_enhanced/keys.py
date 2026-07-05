"""GTA V Enhanced key extraction.

Pipeline (all mirrored from CodeWalker's `GTAKeys.UseMagicData` /
`GenerateV2`):

1. Scan `GTA5_Enhanced.exe` for a 32-byte window whose SHA1 equals
   ``PC_AES_KEY_HASH``. The result is the per-user AES key.
2. Take the embedded ``magic.dat`` (154069 bytes, SHA256
   ``dc35981f822e892ced3aa81d31e7a96927d573ee28f67417592b5afeaf330832``).
3. Seed a .NET-compatible PRNG with ``(int)JenkHash.GenHash(PC_AES_KEY)``
   and pull four byte streams ``rb1..rb4`` of the same length.
4. ``db[i] = (magic[i] - rb1[i] - rb2[i] - rb3[i] - rb4[i]) & 0xFF``.
5. AES-256-ECB decrypt of ``db`` with ``PC_AES_KEY``.
6. Raw-DEFLATE inflate (no zlib header).
7. Slice the 306_272-byte result into:
   * ``[0..27472)``    NG keys  (101 x 272 bytes)
   * ``[27472..306000)`` NG decrypt tables (17 x 16 x 256 x u32)
   * ``[306000..306256)``  LUT (unused here)
   * ``[306256..306272)``  AWC key (unused here)
"""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass
from pathlib import Path

from Crypto.Cipher import AES  # pycryptodome

from .dotnet_random import DotNetRandom
from .jenkhash import jenkins_hash

# Hash shared by both Legacy and Enhanced exes; from
# CodeWalker `GTA5KeyHashes.PC_AES_KEY_HASH`.
PC_AES_KEY_HASH = bytes([
    0xA0, 0x79, 0x61, 0x28, 0xA7, 0x75, 0x72, 0x0A,
    0xC2, 0x04, 0xD9, 0x81, 0x9F, 0x68, 0xC1, 0x72,
    0xE3, 0x95, 0x2C, 0x6D,
])

MAGIC_DAT = (Path(__file__).parent / "magic.dat").read_bytes()
assert len(MAGIC_DAT) == 154_069, f"magic.dat has wrong size: {len(MAGIC_DAT)}"

_NG_KEYS_LEN = 27_472          # 101 * 272
_NG_TABLES_LEN = 278_528       # 17 * 16 * 256 * 4
_LUT_LEN = 256
_AWC_LEN = 16
_INFLATED_LEN = _NG_KEYS_LEN + _NG_TABLES_LEN + _LUT_LEN + _AWC_LEN  # 306_272


@dataclass
class GtaKeys:
    aes_key: bytes              # 32 bytes
    ng_keys: list[bytes]        # 101 entries, each 272 bytes
    ng_decrypt_tables: list[list[list[list[int]]]]  # [17][16][256] of u32

    @classmethod
    def from_enhanced_exe(cls, exe_path: str | Path) -> "GtaKeys":
        exe = Path(exe_path).read_bytes()
        aes_key = _find_aes_key(exe)
        return _derive_from_magic(aes_key)

    @classmethod
    def from_aes_key(cls, aes_key: bytes) -> "GtaKeys":
        if len(aes_key) != 32:
            raise ValueError(f"AES key must be 32 bytes, got {len(aes_key)}")
        return _derive_from_magic(aes_key)

    def save(self, directory: str | Path) -> None:
        """Write the three CodeWalker-style ``gtav_*.dat`` files."""
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        (d / "gtav_aes_key.dat").write_bytes(self.aes_key)
        (d / "gtav_ng_key.dat").write_bytes(b"".join(self.ng_keys))
        tables = bytearray()
        for i in range(17):
            for j in range(16):
                for k in range(256):
                    tables += self.ng_decrypt_tables[i][j][k].to_bytes(4, "little")
        (d / "gtav_ng_decrypt_tables.dat").write_bytes(tables)


def _find_aes_key(exe_data: bytes) -> bytes:
    """Sliding-window SHA1 scan for the 32-byte PC_AES_KEY."""
    target = PC_AES_KEY_HASH
    last = len(exe_data) - 32
    for i in range(last + 1):
        if hashlib.sha1(exe_data[i:i + 32]).digest() == target:
            return exe_data[i:i + 32]
    raise ValueError("AES key not found in GTA5_Enhanced.exe (wrong executable?)")


def _derive_from_magic(aes_key: bytes) -> GtaKeys:
    magic = MAGIC_DAT
    n = len(magic)

    # C# cast `(int)uint` is a bit-for-bit reinterpret; Python handles it
    # by wrapping the unsigned hash into the signed 32-bit range.
    seed_unsigned = jenkins_hash(aes_key)
    seed_signed = seed_unsigned - 0x100000000 if seed_unsigned >= 0x80000000 else seed_unsigned
    rng = DotNetRandom(seed_signed)

    rb1 = bytearray(n); rng.next_bytes(rb1)
    rb2 = bytearray(n); rng.next_bytes(rb2)
    rb3 = bytearray(n); rng.next_bytes(rb3)
    rb4 = bytearray(n); rng.next_bytes(rb4)

    db = bytearray(n)
    for i in range(n):
        db[i] = (magic[i] - rb1[i] - rb2[i] - rb3[i] - rb4[i]) & 0xFF

    # AES-256-ECB, no padding. CodeWalker's `DecryptAESData` operates on
    # `data.Length - data.Length % 16` bytes; the trailing bytes of magic.dat
    # (length 154069 = 16*9629 + 5) are not block-aligned and are passed
    # through untouched. The DeflateStream then reads from the full buffer.
    aligned = len(db) - (len(db) % 16)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(bytes(db[:aligned])) + bytes(db[aligned:])

    # Raw DEFLATE (matches .NET `System.IO.Compression.DeflateStream`).
    # Use a decompressor so trailing garbage after the deflate stream
    # (the unaligned tail) is tolerated, just like DeflateStream does.
    try:
        decomp = zlib.decompressobj(-15)
        inflated = decomp.decompress(decrypted) + decomp.flush()
    except zlib.error as exc:
        raise ValueError(
            "Failed to inflate magic.dat — wrong AES key (wrong exe?)."
        ) from exc

    if len(inflated) < _INFLATED_LEN:
        raise ValueError(
            f"Inflated magic data too small: {len(inflated)} (expected >= {_INFLATED_LEN})"
        )

    ng_keys_blob = inflated[:_NG_KEYS_LEN]
    tables_blob = inflated[_NG_KEYS_LEN:_NG_KEYS_LEN + _NG_TABLES_LEN]

    ng_keys = [ng_keys_blob[i * 272:(i + 1) * 272] for i in range(101)]

    tables: list[list[list[list[int]]]] = []
    off = 0
    for _i in range(17):
        round_tables: list[list[int]] = []
        for _j in range(16):
            row: list[int] = []
            for _k in range(256):
                row.append(int.from_bytes(tables_blob[off:off + 4], "little"))
                off += 4
            round_tables.append(row)
        tables.append(round_tables)

    return GtaKeys(aes_key=aes_key, ng_keys=ng_keys, ng_decrypt_tables=tables)
