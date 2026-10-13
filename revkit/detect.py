"""Binary format detection: PE / ELF / Mach-O / unknown.

Lets revkit behave like `file(1)` for the formats analysts actually see:
Windows PE, Linux ELF and macOS Mach-O, with architecture and PE subtype.
"""
from __future__ import annotations

import struct

PE_EXECUTABLE_IMAGE = 0x0002
PE_DLL = 0x2000
PE_SYS = 0x0008  # native driver image


def detect_type(data: bytes) -> dict:
    """Classify a byte buffer. Returns format/kind/arch/bits."""
    if len(data) >= 2 and data[:2] == b"MZ":
        return _detect_pe(data)
    if data.startswith(b"\x7fELF"):
        return _detect_elf(data)
    if len(data) >= 4 and data[:4] in (
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return _detect_macho(data[:4])
    return {"format": "unknown", "kind": "data", "arch": "unknown",
            "bits": None}


def _detect_pe(data: bytes) -> dict:
    arch = "unknown"
    bits = None
    kind = "pe"
    if len(data) < 0x40:
        return {"format": "pe", "kind": kind, "arch": arch, "bits": bits}
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"format": "pe", "kind": "mz-stub", "arch": arch, "bits": bits}
    (machine, _, _, _, _, _, chars) = struct.unpack_from("<HHIIIHH", data,
                                                         e_lfanew + 4)
    arch_map = {0x014C: ("x86", 32), 0x8664: ("x64", 64),
                0xAA64: ("ARM64", 64), 0x01C0: ("ARM", 32),
                0x5032: ("RISC-V32", 32), 0x5064: ("RISC-V64", 64)}
    if machine in arch_map:
        arch, bits = arch_map[machine]
    if chars & PE_DLL:
        kind = "dll"
    elif chars & PE_SYS:
        kind = "sys"
    elif chars & PE_EXECUTABLE_IMAGE:
        kind = "exe"
    return {"format": "pe", "kind": kind, "arch": arch, "bits": bits}


def _detect_elf(data: bytes) -> dict:
    ei_class = data[4]
    ei_data = data[5]
    bits = 64 if ei_class == 2 else 32
    # machine field: e_machine at offset 18 (LE) or 19 (BE)
    if ei_data == 1:  # little endian
        (machine,) = struct.unpack_from("<H", data, 18)
    else:
        (machine,) = struct.unpack_from(">H", data, 18)
    arch_map = {0x03: "x86", 0x3E: "x64", 0x28: "ARM", 0xB7: "ARM64",
                0xF3: "RISC-V", 0x08: "MIPS"}
    return {"format": "elf", "kind": "elf",
            "arch": arch_map.get(machine, "unknown"), "bits": bits}


def _detect_macho(magic: bytes) -> dict:
    if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        bits = 32
    else:
        bits = 64
    return {"format": "macho", "kind": "macho", "arch": "unknown",
            "bits": bits}
