"""Tests for PE header parsing (real system PE + synthetic bytes)."""
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.pe import NotPE, from_bytes, parse

# A minimal valid PE32+ header (no sections): enough for header parsing.
def _minimal_pe() -> bytes:
    data = bytearray(b"MZ" + b"\x00" * 0x3E)          # 64 bytes total
    struct.pack_into("<I", data, 0x3C, 0x40)          # e_lfanew = 0x40
    data += b"PE\x00\x00"
    data += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)  # COFF (20B)
    opt = struct.pack("<H", 0x20B)                    # magic PE32+ (off 0)
    opt += struct.pack("<BB", 14, 0)                  # linker (off 2)
    opt += struct.pack("<III", 0, 0, 0)               # sizes (off 4)
    opt += struct.pack("<IIQ", 0, 0x1000, 0x140000000)  # entry, basecode, imagebase (16)
    opt += struct.pack("<II", 0x1000, 0x200)          # section/file alignment (32)
    opt += struct.pack("<HH", 6, 0)                   # OS version (40)
    opt += struct.pack("<HH", 0, 0)                   # image version (44)
    opt += struct.pack("<HH", 6, 0)                   # subsystem version (48)
    opt += struct.pack("<I", 0)                       # win32 version (52)
    opt += struct.pack("<III", 0x8000, 0x200, 0)      # image, headers, checksum (56)
    opt += struct.pack("<HH", 3, 0)                   # subsystem, dll chars (68)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap (72)
    opt += struct.pack("<II", 0, 16)                  # loader flags, nrv (104)
    data += opt + b"\x00" * (240 - len(opt))
    return bytes(data)


def test_real_pe_headers():
    # kernel32.dll always exists on Windows and is a PE32+ image
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = parse(str(sample))
    assert pe.dos.magic == "MZ"
    assert pe.optional.is_pe32_plus
    assert pe.optional.image_base > 0
    assert pe.coff.machine_name in ("x64", "ARM64")
    assert pe.coff.number_of_sections > 0
    print("test_real_pe_headers: ok")


def test_synthetic_pe32_plus():
    pe = from_bytes(_minimal_pe(), "synthetic.dll")
    assert pe.dos.e_lfanew == 0x40
    assert pe.coff.machine_name == "x64"
    assert pe.optional.is_pe32_plus
    assert pe.optional.address_of_entry_point == 0
    assert pe.optional.number_of_rva_and_sizes == 16
    print("test_synthetic_pe32_plus: ok")


def test_not_pe():
    try:
        from_bytes(b"hello world" * 10)
        assert False, "should have raised"
    except NotPE:
        pass
    print("test_not_pe: ok")


if __name__ == "__main__":
    test_real_pe_headers()
    test_synthetic_pe32_plus()
    test_not_pe()
    print("revkit header tests passed")
