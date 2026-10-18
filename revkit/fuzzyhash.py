"""Context-triggered piecewise hashing (ssdeep-style fuzzy hash).

Classic similarity hashing for malware/firmware triage: the file is
split at content-triggered boundaries, each chunk is hashed, and the
chunk hashes are compared with a weighted score. This is a minimal,
readable implementation of the algorithm behind ssdeep — no ctypes,
pure stdlib.
"""
from __future__ import annotations

import hashlib

_BS = 64  # rolling-window size
_HS = 6   # hash output size (chars)


def _rolling(window: list, remove: int, add: int) -> int:
    h = 0
    for b in window:
        h = (h * 31 + b) & 0xFFFFFFFF
    return h


def fuzzy_hash(data: bytes, block: int = 32) -> str:
    """Return a fuzzy hash string: ``b64(block):b64(chunks)``.

    The block size doubles when fewer than half the trigger points
    fire, mirroring ssdeep's two-stage fallback.
    """
    if not data:
        return "0:0"
    h1 = fuzzy_hash_block(data, block)
    h2 = fuzzy_hash_block(data, block * 2) if len(h1) < 6 else ""
    return f"{_b64(block):s}:{h1}{':' + h2 if h2 else ''}"


def fuzzy_hash_block(data: bytes, block: int) -> str:
    chunks = []
    window = []
    h = 0
    for i, b in enumerate(data):
        window.append(b)
        if len(window) > _BS:
            h = (h * 31 - window.pop(0) * pow(31, _BS - 1) +
                 b) & 0xFFFFFFFF
        if h % block == block - 1 or i == len(data) - 1:
            chunks.append(hashlib.md5(bytes(window)).hexdigest()[:_HS])
            window = []
    return "".join(chunks)


def _b64(n: int) -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = ""
    while n:
        out = chars[n % 64] + out
        n //= 64
    return out or "0"


def fuzzy_compare(a: str, b: str) -> int:
    """Score two fuzzy hashes 0-100 (same block size only)."""
    if not a or not b:
        return 0
    try:
        b1, rest1 = a.split(":", 1)
        b2, rest2 = b.split(":", 1)
        if b1 != b2:
            return 0
        c1, c2 = rest1.split(":")[0], rest2.split(":")[0]
    except ValueError:
        return 0
    if not c1 or not c2:
        return 0
    # weighted by shared chunk count over the longer digest
    s1, s2 = len(c1), len(c2)
    common = sum(1 for i in range(min(s1, s2)) if c1[i] == c2[i])
    return int(100 * (2 * common) / (s1 + s2)) if (s1 + s2) else 0
