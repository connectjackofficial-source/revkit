"""Tests for binary format detection."""
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.detect import detect_type


def test_pe_dll():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    info = detect_type(sample.read_bytes())
    assert info["format"] == "pe"
    assert info["kind"] == "dll"
    assert info["arch"] == "x64"
    assert info["bits"] == 64
    print("test_pe_dll: ok")


def test_pe_exe():
    sample = Path(r"C:\Windows\System32\notepad.exe")
    if not sample.exists():
        return
    info = detect_type(sample.read_bytes())
    assert info["format"] == "pe"
    assert info["kind"] in ("exe", "dll")
    print("test_pe_exe: ok")


def test_elf():
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # e_ident (16B)
    hdr += struct.pack("<H", 0x02)  # e_type
    hdr += struct.pack("<H", 0x3E)  # e_machine = x86-64
    hdr += b"\x00" * 8
    info = detect_type(hdr)
    assert info["format"] == "elf"
    assert info["arch"] == "x64"
    assert info["bits"] == 64
    print("test_elf: ok")


def test_macho():
    for magic, bits in ((b"\xfe\xed\xfa\xcf", 64), (b"\xce\xfa\xed\xfe", 32)):
        info = detect_type(magic + b"\x00" * 12)
        assert info["format"] == "macho"
        assert info["bits"] == bits
    print("test_macho: ok")


def test_unknown():
    info = detect_type(b"just some plain text data here")
    assert info["format"] == "unknown"
    print("test_unknown: ok")


if __name__ == "__main__":
    test_pe_dll()
    test_pe_exe()
    test_elf()
    test_macho()
    test_unknown()
    print("revkit detect tests passed")
