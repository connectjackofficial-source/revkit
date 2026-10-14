"""Overlay detection: data appended past the last section.

Many droppers and injectors append a second payload (a config blob, an
encrypted stage, an embedded archive) after the last section's raw data.
Spotting the overlay is often the fastest path from "weird file" to
"malicious sample".
"""
from __future__ import annotations

from .pe import PE


def overlay_info(pe: PE) -> dict:
    """Locate data that lives past the last section.

    Returns {"present": bool, "offset": int, "size": int,
    "entropy_hint": str} — entropy_hint is a coarse label ("low"/"high")
    so a quick glance tells you whether the overlay is likely compressed
    or encrypted.
    """
    data = pe.data
    if pe.sections:
        last_end = max(s.pointer_to_raw_data + s.size_of_raw_data
                       for s in pe.sections)
    else:
        # no sections: everything after the headers is the overlay
        last_end = pe.dos.e_lfanew + 24 + pe.coff.size_of_optional_header
    overlay = data[last_end:]
    hint = "clean"
    if overlay:
        from .entropy import shannon_entropy
        e = shannon_entropy(overlay)
        hint = "high" if e > 7.0 else ("mid" if e > 5.0 else "low")
    return {"present": len(overlay) > 0, "offset": last_end,
            "size": len(overlay), "entropy_hint": hint}
