"""Tests for overlay detection."""
import random
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.overlay import overlay_info
from revkit.pe import from_bytes, parse


def _pe_with_sections(content=b"\x90" * 0x200, extra=b""):
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
    data += opt + b"\x00" * (240 - len(opt))
    n = b".text" + b"\x00" * 3
    ptr = 0x400
    data += (n + struct.pack("<IIIIII", len(content), 0x1000,
                             len(content), ptr, 0, 0)
             + struct.pack("<HH", 0, 0) + struct.pack("<I", 0x60000020))
    # pad so the section content lands at the declared raw offset 0x400
    data += b"\x00" * (ptr - len(data))
    return bytes(data) + content + extra


def test_clean_no_overlay():
    pe = from_bytes(_pe_with_sections(), "clean.exe")
    info = overlay_info(pe)
    assert info["present"] is False
    assert info["size"] == 0
    assert info["entropy_hint"] == "clean"
    print("test_clean_no_overlay: ok")


def test_overlay_detected():
    blob = b"PAYLOAD_CONFIG_V2" + b"\x00" * 20
    pe = from_bytes(_pe_with_sections(extra=blob), "injected.exe")
    info = overlay_info(pe)
    assert info["present"] is True
    assert info["size"] == len(blob)
    assert info["offset"] == 0x400 + 0x200
    assert info["entropy_hint"] in ("low", "mid")
    print("test_overlay_detected: ok")


def test_high_entropy_overlay():
    r = random.Random(11)
    blob = bytes(r.randrange(256) for _ in range(0x1000))
    pe = from_bytes(_pe_with_sections(extra=blob), "packed-overlay.exe")
    info = overlay_info(pe)
    assert info["present"] is True
    assert info["entropy_hint"] == "high"
    print("test_high_entropy_overlay: ok")


def test_real_pe_overlay():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = parse(str(sample))
    info = overlay_info(pe)
    # kernel32 ships with a signature/rich-data tail; overlay is common
    assert info["offset"] >= 0 and info["size"] >= 0
    print("test_real_pe_overlay: ok")


if __name__ == "__main__":
    test_clean_no_overlay()
    test_overlay_detected()
    test_high_entropy_overlay()
    test_real_pe_overlay()
    print("revkit overlay tests passed")
