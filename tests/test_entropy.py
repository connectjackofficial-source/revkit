"""Tests for entropy and packer heuristics."""
import os
import random
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.entropy import packer_score, section_entropies, shannon_entropy
from revkit.pe import from_bytes


def test_entropy_extremes():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    r = random.Random(7)
    rnd = bytes(r.randrange(256) for _ in range(4096))
    e = shannon_entropy(rnd)
    assert 7.5 < e <= 8.0  # uniform random is close to 8 bits/byte
    print("test_entropy_extremes: ok")


def _pe_with_sections(sections):
    data = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", data, 0x3C, 0x40)
    data += b"PE\x00\x00"
    data += struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 240, 0x22)
    opt = struct.pack("<H", 0x20B)
    opt += struct.pack("<BB", 14, 0)
    opt += struct.pack("<III", 0, 0, 0)
    opt += struct.pack("<IIQ", 0x1000, 0x1000, 0x140000000)
    opt += struct.pack("<II", 0x1000, 0x200)
    opt += struct.pack("<HH", 6, 0)
    opt += struct.pack("<HH", 0, 0)
    opt += struct.pack("<HH", 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<III", 0x8000, 0x200, 0)
    opt += struct.pack("<HH", 3, 0)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    data += opt + b"\x00" * (240 - len(opt))
    blob = bytearray()
    for i, (name, content) in enumerate(sections):
        n = (name.encode() + b"\x00" * 8)[:8]
        ptr = 0x400 + len(blob)
        data += (n + struct.pack("<IIIIII", len(content), 0x1000 * (i + 1),
                                 len(content), ptr, 0, 0)
                 + struct.pack("<HH", 0, 0) + struct.pack("<I", 0x60000020))
        blob += content
    return bytes(data) + bytes(blob)


def test_normal_pe_low_score():
    text = b"\x90" * 0x2000  # NOP sled: very low entropy
    data = b"\x00\x00\x00\x00" * 0x2000
    pe = from_bytes(_pe_with_sections([(".text", text), (".data", data)]),
                    "normal.dll")
    info = packer_score(pe)
    assert info["score"] <= 20
    assert "upx_sections" not in info["flags"]
    print("test_normal_pe_low_score: ok")


def test_upx_style_pe_high_score():
    r = random.Random(3)
    rnd = bytes(r.randrange(256) for _ in range(0x9000))
    pe = from_bytes(_pe_with_sections([(".text", b"\x90" * 0x200),
                                       ("UPX0", rnd), ("UPX1", rnd)]),
                    "packed.exe")
    info = packer_score(pe)
    assert "upx_sections" in info["flags"]
    assert info["score"] >= 90
    print("test_upx_style_pe_high_score: ok")


def test_real_pe_section_entropies():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    from revkit.pe import parse
    pe = parse(str(sample))
    ent = section_entropies(pe)
    assert len(ent) == len(pe.sections)
    assert all(0 <= e["entropy"] <= 8 for e in ent)
    info = packer_score(pe)
    assert "upx_sections" not in info["flags"]
    print("test_real_pe_section_entropies: ok")


if __name__ == "__main__":
    test_entropy_extremes()
    test_normal_pe_low_score()
    test_upx_style_pe_high_score()
    test_real_pe_section_entropies()
    print("revkit entropy tests passed")
