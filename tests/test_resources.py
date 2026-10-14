"""Tests for revkit PE resource enumeration."""
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.pe import from_bytes
from revkit.resources import RESOURCE_TYPES, get_resources


def _pe_with_resources() -> bytes:
    data = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", data, 0x3C, 0x40)
    data += b"PE\x00\x00"
    data += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
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
    # 16 data directory entries; index 2 = resources (RVA 0x2000, 0x80)
    dirs = [(0, 0)] * 16
    dirs[2] = (0x2000, 0x80)
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)
    data += opt + b"\x00" * (240 - len(opt))
    n = b".rsrc" + b"\x00" * 3
    data += (n + struct.pack("<IIIIII", 0x400, 0x2000, 0x400, 0x2000, 0, 0)
             + struct.pack("<HH", 0, 0) + struct.pack("<I", 0x40000040))
    # resource root directory at RVA 0x2000: 2 named + 1 id entries
    # IMAGE_RESOURCE_DIRECTORY: Characteristics(4) TimeDateStamp(4)
    #   Major(2) Minor(2) NumberOfNamed(2) NumberOfId(2) = 16 bytes
    root = bytearray()
    root += struct.pack("<IIHHHH", 0, 0, 0, 0, 2, 1)
    # type 16 (VERSION): offset 0x28 -> one child
    root += struct.pack("<II", 16, 0x28)
    # type 24 (MANIFEST): offset 0x38 -> two children
    root += struct.pack("<II", 24, 0x38)
    # type 10 (RCDATA): offset 0x48 -> one child
    root += struct.pack("<II", 10, 0x48)
    # child dirs (16B each): n_named/n_id + 0s
    for cnt in (1, 2, 1):
        root += struct.pack("<IIHHHH", 0, 0, 0, 0, cnt, 0)
    root += b"\x00" * (0x400 - len(root))
    data += b"\x00" * (0x2000 - len(data))
    data += root
    return bytes(data)


def test_resource_types_present():
    pe = from_bytes(_pe_with_resources(), "res.exe")
    res = get_resources(pe)
    ids = {r["type_id"] for r in res}
    assert 16 in ids and 24 in ids and 10 in ids
    by_id = {r["type_id"]: r for r in res}
    assert by_id[16]["type"] == "VERSION"
    assert by_id[24]["type"] == "MANIFEST"
    assert by_id[10]["type"] == "RCDATA"
    assert by_id[24]["entries"] == 2
    print("test_resource_types_present: ok")


def test_resource_names_are_friendly():
    pe = from_bytes(_pe_with_resources(), "res.exe")
    res = get_resources(pe)
    assert all(r["type"] in RESOURCE_TYPES.values() for r in res)
    print("test_resource_names_are_friendly: ok")


def test_no_resources():
    data = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", data, 0x3C, 0x40)
    data += b"PE\x00\x00"
    data += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
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
    for _ in range(16):
        opt += struct.pack("<II", 0, 0)
    data += opt + b"\x00" * (240 - len(opt))
    pe = from_bytes(bytes(data), "nores.exe")
    assert get_resources(pe) == []
    print("test_no_resources: ok")


def test_real_pe_resources():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = from_bytes(sample.read_bytes(), "kernel32.dll")
    res = get_resources(pe)
    assert isinstance(res, list)
    print(f"test_real_pe_resources: {len(res)} types "
          f"({[r['type'] for r in res[:4]]})")


if __name__ == "__main__":
    test_resource_types_present()
    test_resource_names_are_friendly()
    test_no_resources()
    test_real_pe_resources()
    print("revkit resources tests passed")
