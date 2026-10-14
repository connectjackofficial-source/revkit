"""ELF parsing: file header + program header table (segments).

ELF 64/32 headers and PT_* segments are the first things a reverser
checks after `file` — entry point, load bias, interpreter, and which
segments are writable+executable (the classic shellcode home).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


class NotELF(Exception):
    pass


def _unpack(fmt, data, off, label):
    try:
        return struct.unpack_from(fmt, data, off)
    except struct.error as exc:
        raise NotELF(f"bad ELF {label} at offset 0x{off:x}: {exc}")


@dataclass
class ELF:
    data: bytes
    e_type: int
    e_machine: int
    e_entry: int
    isa: str          # e.g. "x86-64"
    bits: int         # 32 or 64
    endian: str       # "little" / "big"
    segments: list = field(default_factory=list)

    @property
    def is_shared_object(self) -> bool:
        return self.e_type == 3  # ET_DYN

    @property
    def machine_name(self) -> str:
        names = {0x3E: "x86-64", 0x03: "i386", 0x28: "arm",
                 0xB7: "aarch64", 0xF3: "riscv", 0x08: "mips",
                 0x14: "powerpc"}
        return names.get(self.e_machine, f"machine_0x{self.e_machine:x}")


ELF_64 = "<16sHHIQQQIHHHHHH"
ELF_32 = "<16sHHIIIIIHHHHHH"


def parse(data: bytes) -> ELF:
    if not data.startswith(b"\x7fELF"):
        raise NotELF("missing ELF magic")
    ident = data[:16]
    bits = 64 if ident[4] == 2 else 32
    endian = "big" if ident[5] == 2 else "little"
    fmt = "<" if endian == "little" else ">"
    hdr = _unpack(fmt + (ELF_64 if bits == 64 else ELF_32)[1:],
                  data, 0, "header")
    e_type, e_machine, e_entry = hdr[1], hdr[2], hdr[4]
    e_phoff = hdr[5]
    e_phentsize, e_phnum = (hdr[9], hdr[10]) if bits == 64 else (hdr[8], hdr[9])
    elf = ELF(data=data, e_type=e_type, e_machine=e_machine,
              e_entry=e_entry, isa="", bits=bits, endian=endian)
    elf.isa = elf.machine_name
    if e_phnum and e_phentsize:
        elf.segments = _segments(data, e_phoff, e_phnum, e_phentsize,
                                 bits, endian)
    return elf


def _segments(data, phoff, phnum, phentsize, bits, endian) -> list:
    fmt = "<" if endian == "little" else ">"
    seg_fmt = fmt + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
    seg_size = 56 if bits == 64 else 32
    if phentsize < seg_size:
        return []
    types = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP",
             4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS",
             0x6474e551: "GNU_EH_FRAME", 0x6474e550: "GNU_STACK",
             0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY"}
    segs = []
    for i in range(phnum):
        off = phoff + i * seg_size
        try:
            vals = struct.unpack_from(seg_fmt, data, off)
        except struct.error:
            break
        p_type, p_flags = vals[0], vals[1]
        if bits == 64:
            p_offset, p_vaddr, p_filesz, p_memsz = vals[2], vals[3], vals[5], vals[6]
        else:
            p_offset, p_vaddr, p_filesz, p_memsz = vals[2], vals[3], vals[5], vals[6]
        segs.append({"type": types.get(p_type, f"0x{p_type:x}"),
                     "flags": p_flags, "offset": p_offset,
                     "vaddr": p_vaddr, "filesz": p_filesz,
                     "memsz": p_memsz})
    return segs
