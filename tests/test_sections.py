"""Tests for PE section table parsing."""
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.pe import from_bytes, parse, rva_to_offset


def _pe_with_sections() -> bytes:
    data = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", data, 0x3C, 0x40)
    data += b"PE\x00\x00"
    # COFF: 2 sections, opt size 240
    data += struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x22)
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
    # section table: .text and .data
    def sec(name, vsize, vaddr, rawsize, ptr, chars):
        n = (name + b"\x00" * 8)[:8]
        return (n + struct.pack("<IIIIII", vsize, vaddr, rawsize, ptr, 0, 0)
                + struct.pack("<HH", 0, 0) + struct.pack("<I", chars))
    data += sec(b".text", 0x1000, 0x1000, 0x200, 0x400, 0x60000020)
    data += sec(b".data", 0x800, 0x2000, 0x100, 0x600, 0xC0000040)
    return bytes(data)


def test_synthetic_sections():
    pe = from_bytes(_pe_with_sections(), "s.dll")
    assert len(pe.sections) == 2
    assert pe.sections[0].name == ".text"
    assert pe.sections[0].virtual_address == 0x1000
    assert pe.sections[1].name == ".data"
    print("test_synthetic_sections: ok")


def test_real_pe_sections():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = parse(str(sample))
    names = [s.name for s in pe.sections]
    assert len(pe.sections) > 0
    assert ".text" in names or "PAGE" in names
    assert all(s.size_of_raw_data >= 0 for s in pe.sections)
    print("test_real_pe_sections: ok")


def test_rva_to_offset_roundtrip():
    pe = from_bytes(_pe_with_sections(), "s.dll")
    # .text vaddr 0x1000 -> ptr 0x400
    assert rva_to_offset(pe, 0x1000) == 0x400
    assert rva_to_offset(pe, 0x1100) == 0x500
    # .data vaddr 0x2000 -> ptr 0x600
    assert rva_to_offset(pe, 0x2000) == 0x600
    # outside any section -> unchanged
    assert rva_to_offset(pe, 0x9999) == 0x9999
    print("test_rva_to_offset_roundtrip: ok")


if __name__ == "__main__":
    test_synthetic_sections()
    test_real_pe_sections()
    test_rva_to_offset_roundtrip()
    print("revkit section tests passed")
