"""Reimplementation of .NET Framework's `System.Random`.

Byte-for-byte port of the Microsoft reference source
(https://github.com/microsoft/referencesource/blob/master/mscorlib/system/random.cs)
so that `NextBytes(buf)` produces exactly what C#
`new Random(seed).NextBytes(buf)` does — which is what CodeWalker uses
when deobfuscating `magic.dat`.
"""

from __future__ import annotations

_MBIG = 0x7FFFFFFF           # Int32.MaxValue
_MSEED = 161_803_398


def _i32(x: int) -> int:
    """Wrap a Python int into the signed 32-bit range, like a C# `int`."""
    x &= 0xFFFFFFFF
    if x >= 0x80000000:
        x -= 0x100000000
    return x


class DotNetRandom:
    __slots__ = ("_seed_array", "_inext", "_inextp")

    def __init__(self, seed: int) -> None:
        # C# `(int)uint` reinterpret then signed int semantics.
        seed = _i32(seed)

        # subtraction = (Seed == Int32.MinValue) ? Int32.MaxValue : Math.Abs(Seed)
        if seed == -0x80000000:
            subtraction = _MBIG
        else:
            subtraction = -seed if seed < 0 else seed

        seed_array = [0] * 56

        # mj, mk are C# `int` — every operation wraps to int32.
        mj = _i32(_MSEED - subtraction)
        seed_array[55] = mj
        mk = 1

        for i in range(1, 55):
            ii = (21 * i) % 55
            seed_array[ii] = mk
            mk = _i32(mj - mk)
            if mk < 0:
                mk += _MBIG
            mj = seed_array[ii]

        for _k in range(1, 5):
            for i in range(1, 56):
                idx = 1 + ((i + 30) % 55)
                seed_array[i] = _i32(seed_array[i] - seed_array[idx])
                if seed_array[i] < 0:
                    seed_array[i] += _MBIG

        self._seed_array = seed_array
        self._inext = 0
        self._inextp = 21

    def _internal_sample(self) -> int:
        loc_inext = self._inext + 1
        if loc_inext >= 56:
            loc_inext = 1
        loc_inextp = self._inextp + 1
        if loc_inextp >= 56:
            loc_inextp = 1

        ret = _i32(self._seed_array[loc_inext] - self._seed_array[loc_inextp])
        if ret == _MBIG:
            ret -= 1
        if ret < 0:
            ret += _MBIG
        self._seed_array[loc_inext] = ret

        self._inext = loc_inext
        self._inextp = loc_inextp
        return ret

    def next_bytes(self, buffer: bytearray) -> None:
        # C#: `(byte)(InternalSample() % (Byte.MaxValue + 1))` -> 0..255
        for i in range(len(buffer)):
            buffer[i] = self._internal_sample() % 256
