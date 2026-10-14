"""Tests for revkit ELF parsing."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.elf import NotELF, parse


def _elf64(phdr: bytes = b"", e_phnum: int = 0) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_type, e_machine = 3, 0x3E  # ET_DYN, x86-64
    data = bytearray(ident)
    data += struct.pack("<HHIQQQIHHHHHH",
                        e_type, e_machine, 1, 0x401000, 0x40, 0, 0,
                        64, 56, e_phnum, 64, 0, 0)
    data += phdr
    return bytes(data)


def _phdr64(ptype, flags, offset, vaddr, filesz, memsz):
    return struct.pack("<IIQQQQQQ", ptype, flags, offset, vaddr,
                       vaddr, filesz, memsz, 0x1000)


def test_header_fields():
    elf = parse(_elf64())
    assert elf.machine_name == "x86-64"
    assert elf.bits == 64
    assert elf.endian == "little"
    assert elf.is_shared_object is True
    assert elf.e_entry == 0x401000
    print("test_header_fields: ok")


def test_segments():
    ph = (_phdr64(6, 4, 0x40, 0x400040, 0x1000, 0x1000)   # PHDR
          + _phdr64(1, 6, 0, 0, 0x2000, 0x2000)            # LOAD rwx
          + _phdr64(3, 4, 0x300, 0x300300, 0x40, 0x40))    # INTERP
    elf = parse(_elf64(ph, e_phnum=3))
    assert len(elf.segments) == 3
    assert elf.segments[0]["type"] == "PHDR"
    assert elf.segments[1]["type"] == "LOAD"
    assert elf.segments[1]["flags"] == 6  # RWX segment present
    assert elf.segments[2]["type"] == "INTERP"
    print("test_segments: ok")


def test_not_elf():
    try:
        parse(b"this is not an elf file at all")
        assert False, "should have raised"
    except NotELF:
        pass
    print("test_not_elf: ok")


def test_truncated():
    try:
        parse(b"\x7fELF" + b"\x00" * 10)
        assert False, "should have raised"
    except NotELF:
        pass
    print("test_truncated: ok")


if __name__ == "__main__":
    test_header_fields()
    test_segments()
    test_not_elf()
    test_truncated()
    print("revkit elf tests passed")
