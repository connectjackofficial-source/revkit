"""PE resource directory: what the binary embeds.

The resource table answers "what does this program claim to be": an
icon, a version stamp, an embedded manifest or a config blob (RCDATA).
Malware often hides payloads in RCDATA; toolkits detect it by the
resource shape before ever touching the code.
"""
from __future__ import annotations

import struct

from .pe import rva_to_offset

RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
    10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
    21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}


def _data_directories_offset(pe) -> int:
    opt_off = pe.dos.e_lfanew + 24
    return opt_off + (112 if pe.optional.is_pe32_plus else 96)


def _resource_root(pe) -> int:
    data = pe.data
    dirs_off = _data_directories_offset(pe)
    (rva, _size) = struct.unpack_from("<II", data, dirs_off + 16)  # index 2
    if not rva:
        return 0
    return rva_to_offset(pe, rva)


def _name_or_id(raw: int) -> str:
    if raw & 0x80000000:
        return f"name_0x{raw & 0x7FFFFFFF:x}"
    return str(raw)


def get_resources(pe) -> list:
    """Top-level resource entries.

    Returns [{"type": "ICON", "type_id": 3, "entries": 2}, ...] — one row
    per resource type present in the binary, with the number of names
    under it.
    """
    root = _resource_root(pe)
    if not root:
        return []
    data = pe.data
    # IMAGE_RESOURCE_DIRECTORY: Characteristics(4) TimeDateStamp(4)
    # Major(2) Minor(2) NumberOfNamed(2) NumberOfId(2) = 16 bytes
    (n_named, n_id) = struct.unpack_from("<HH", data, root + 12)
    out = []
    base = root + 16
    for i in range(n_named + n_id):
        (name_raw, entry_raw) = struct.unpack_from("<II", data,
                                                   base + i * 8)
        child_off = root + (entry_raw & 0x7FFFFFFF)
        (cn, ci) = struct.unpack_from("<HH", data, child_off + 12)
        type_name = RESOURCE_TYPES.get(name_raw,
                                       _name_or_id(name_raw))
        out.append({"type": type_name, "type_id": name_raw,
                    "entries": cn + ci})
    return out
