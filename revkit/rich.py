"""PE Rich Header extraction.

The Rich header (a leftover of the VS linker) is a XOR-obfuscated
product-id table that fingerprints the exact compiler/toolchain used to
build a PE. This module decrypts it with the classic algorithm: the
decoder value is ``uint32(Rich+4) ^ 0x536E6144`` ("DanS"), and the
table starts right after the 16-byte block whose last word decrypts to
the same "DanS" magic.
"""
from __future__ import annotations

import struct

_MAGIC = b"Rich"
_DANS = 0x536E6144


def rich_header(data: bytes) -> dict | None:
    """Parse and decrypt the Rich header.

    Returns {"xor_key": int, "entries": [{"product": int, "build": int,
    "count": int}, ...], "offset": int} or None when absent.
    """
    i = data.find(_MAGIC)
    if i < 0 or i + 8 > len(data):
        return None
    key = struct.unpack("<I", data[i + 4:i + 8])[0] ^ _DANS

    start = None
    off = i
    while off >= 0:
        if off + 16 <= len(data):
            marker = struct.unpack("<I", data[off + 12:off + 16])[0]
            if marker == _DANS ^ key:
                start = off + 16
                break
        off -= 16
    if start is None:
        return None

    entries = []
    for off in range(start, i, 16):
        val = struct.unpack("<I", data[off:off + 4])[0]
        count = struct.unpack("<I", data[off + 4:off + 8])[0]
        build = struct.unpack("<I", data[off + 8:off + 12])[0]
        prod = val ^ key
        if 0 < count < 1_000_000:  # sanity
            entries.append({"product": prod, "build": build, "count": count})
    if not entries:
        return None
    entries.reverse()  # table is stored newest-first
    return {"xor_key": key, "entries": entries, "offset": start}
