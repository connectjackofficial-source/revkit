"""Tests for revkit batch 3: fuzzy hash, byte distribution, Rich header."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.fuzzyhash import fuzzy_hash, fuzzy_compare
from revkit.bytes import byte_distribution
from revkit.rich import rich_header


def test_fuzzy_similar_self():
    a = fuzzy_hash(b"hello world " * 20)
    b = fuzzy_hash(b"hello world " * 21)
    assert fuzzy_compare(a, b) >= 90, (a, b)
    print("test_fuzzy_similar_self: ok")


def test_fuzzy_different():
    a = fuzzy_hash(b"a" * 400)
    b = fuzzy_hash(b"b" * 400)
    assert fuzzy_compare(a, b) < 30, (a, b)
    print("test_fuzzy_different: ok")


def test_byte_distribution_shape():
    r = byte_distribution(b"abcabcabc" + bytes(range(256)) * 2)
    assert r["distinct"] == 256
    assert r["total"] == 9 + 512
    assert r["entropy"] > 7.5
    assert 0 <= r["random_score"] <= 100
    assert len(r["top"]) == 16
    print("test_byte_distribution_shape: ok")


def test_byte_distribution_skewed():
    r = byte_distribution(b"\x00" * 1000 + b"AB")
    assert r["random_score"] < 20, r
    assert r["top"][0][0] == 0
    print("test_byte_distribution_skewed: ok")


def test_rich_header_roundtrip():
    # build a fake PE tail: marker block + 2 entries + xor-masked Rich
    key = 0x1234ABCD
    masked = key ^ 0x536E6144
    ents = [(0x123, 0x1000, 3), (0x456, 0x2000, 7)]
    raw = b""
    for prod, build, cnt in reversed(ents):
        raw += struct.pack("<IIII", prod ^ key, cnt, build ^ key, 0)
    marker = struct.pack("<IIII", 0, 0, 0, masked)
    data = marker + raw + b"Rich" + struct.pack("<I", masked) + b"\x00" * 8
    r = rich_header(data)
    assert r is not None
    assert r["xor_key"] == key
    assert [(e["product"], e["count"]) for e in r["entries"]] == \
        [(0x123, 3), (0x456, 7)], r
    print("test_rich_header_roundtrip: ok")


if __name__ == "__main__":
    test_fuzzy_similar_self()
    test_fuzzy_different()
    test_byte_distribution_shape()
    test_byte_distribution_skewed()
    test_rich_header_roundtrip()
    print("revkit batch3 tests passed")
