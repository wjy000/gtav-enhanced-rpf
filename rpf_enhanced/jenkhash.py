"""Jenkins one-at-a-time hash.

Direct port of CodeWalker's `JenkHash.GenHash(byte[])` from
`CodeWalker.Core/GameFiles/Utils/Jenk.cs`. Operates on raw bytes,
no case folding.
"""

from __future__ import annotations

_MASK = 0xFFFFFFFF


def jenkins_hash(data: bytes) -> int:
    """32-bit Jenkins one-at-a-time hash of raw bytes (unsigned)."""
    h = 0
    for b in data:
        h = (h + b) & _MASK
        h = (h + ((h << 10) & _MASK)) & _MASK
        h ^= h >> 6
    h = (h + ((h << 3) & _MASK)) & _MASK
    h ^= h >> 11
    h = (h + ((h << 15) & _MASK)) & _MASK
    return h
