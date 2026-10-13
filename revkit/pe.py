"""PE parsing: DOS / COFF / optional headers.

Pure struct.unpack, no third-party deps. This module grows feature by
feature: headers first, then sections, imports and exports.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B

IMAGE_FILE_MACHINE = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x01F0: "PowerPC",
    0x5032: "RISC-V32",
    0x5064: "RISC-V64",
}


class NotPE(Exception):
    """Raised when the file is not a valid PE image."""


@dataclass
class DosHeader:
    magic: str
    e_lfanew: int


@dataclass
class CoffHeader:
    machine: int
    machine_name: str
    number_of_sections: int
    time_date_stamp: int
    size_of_optional_header: int
    characteristics: int


@dataclass
class OptionalHeader:
    magic: int
    is_pe32_plus: bool
    address_of_entry_point: int
    image_base: int
    size_of_image: int
    subsystem: int
    number_of_rva_and_sizes: int


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


@dataclass
class PE:
    path: str
    dos: DosHeader
    coff: CoffHeader
    optional: OptionalHeader
    sections: list = field(default_factory=list)


def parse(path: str) -> PE:
    data = open(path, "rb").read()
    return from_bytes(data, path)


def from_bytes(data: bytes, path: str = "<bytes>") -> PE:
    if len(data) < 64 or data[:2] != b"MZ":
        raise NotPE("missing MZ DOS signature")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise NotPE("missing PE signature")
    dos = DosHeader(magic="MZ", e_lfanew=e_lfanew)

    coff_off = e_lfanew + 4
    (machine, nsec, ts, _, _, opt_size, chars) = struct.unpack_from(
        "<HHIIIHH", data, coff_off)
    coff = CoffHeader(
        machine=machine,
        machine_name=IMAGE_FILE_MACHINE.get(machine, "unknown"),
        number_of_sections=nsec,
        time_date_stamp=ts,
        size_of_optional_header=opt_size,
        characteristics=chars,
    )

    opt_off = coff_off + 20
    (magic,) = struct.unpack_from("<H", data, opt_off)
    if magic == PE32_PLUS_MAGIC:
        (entry, _base_of_code) = struct.unpack_from("<II", data, opt_off + 16)
        (image_base_lo,) = struct.unpack_from("<I", data, opt_off + 24)
        (image_base_hi,) = struct.unpack_from("<I", data, opt_off + 28)
        image_base = image_base_lo | (image_base_hi << 32)
        (size_of_image,) = struct.unpack_from("<I", data, opt_off + 56)
        (subsystem,) = struct.unpack_from("<H", data, opt_off + 68)
        nrv = struct.unpack_from("<I", data, opt_off + 108)[0]
    elif magic == PE32_MAGIC:
        (entry, image_base) = struct.unpack_from("<II", data, opt_off + 16)
        (size_of_image,) = struct.unpack_from("<I", data, opt_off + 56)
        (subsystem,) = struct.unpack_from("<H", data, opt_off + 68)
        nrv = struct.unpack_from("<I", data, opt_off + 92)[0]
    else:
        raise NotPE(f"unknown optional header magic 0x{magic:04x}")

    optional = OptionalHeader(
        magic=magic,
        is_pe32_plus=magic == PE32_PLUS_MAGIC,
        address_of_entry_point=entry,
        image_base=image_base,
        size_of_image=size_of_image,
        subsystem=subsystem,
        number_of_rva_and_sizes=nrv,
    )

    sections = []
    sec_off = opt_off + coff.size_of_optional_header
    for i in range(coff.number_of_sections):
        raw = data[sec_off + i * 40: sec_off + i * 40 + 40]
        name = raw[:8].rstrip(b"\x00").decode("latin-1")
        (vsize, vaddr, rawsize, ptr, _, _) = struct.unpack_from("<IIIIII", raw, 8)
        (chars,) = struct.unpack_from("<I", raw, 36)
        sections.append(Section(name=name, virtual_size=vsize,
                                virtual_address=vaddr,
                                size_of_raw_data=rawsize,
                                pointer_to_raw_data=ptr,
                                characteristics=chars))

    return PE(path=path, dos=dos, coff=coff, optional=optional,
              sections=sections)


def rva_to_offset(pe: PE, rva: int) -> int:
    """Translate an RVA into a file offset via the section table."""
    for sec in pe.sections:
        start = sec.virtual_address
        end = start + max(sec.virtual_size, sec.size_of_raw_data)
        if start <= rva < end:
            return sec.pointer_to_raw_data + (rva - start)
    return rva
