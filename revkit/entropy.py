"""Entropy analysis: Shannon entropy per section + packer heuristics.

High-entropy regions are the classic signal of compressed or encrypted
payloads; combined with section naming (UPX0/UPX1) this is enough to flag
most commercial packers without loading a single third-party dependency.
"""
from __future__ import annotations

import math
from collections import Counter

from .pe import PE


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def section_entropies(pe: PE) -> list:
    """Per-section entropy. [{"name", "size", "entropy"}]."""
    out = []
    data = pe.data
    for sec in pe.sections:
        start = sec.pointer_to_raw_data
        raw = data[start:start + sec.size_of_raw_data]
        out.append({"name": sec.name, "size": len(raw),
                    "entropy": round(shannon_entropy(raw), 3)})
    return out


HIGH_ENTROPY = 7.0


def packer_score(pe: PE) -> dict:
    """Heuristic packer/cryptor detection. Returns score (0-100) + flags."""
    ent = section_entropies(pe)
    if not ent:
        return {"score": 0, "flags": [], "sections": ent}
    flags = []
    score = 0

    high = [s for s in ent if s["entropy"] > HIGH_ENTROPY]
    if high:
        score += 40
        flags.append("high_entropy_sections")

    upx = [s for s in ent if s["name"].upper().startswith("UPX")]
    if upx:
        score += 50
        flags.append("upx_sections")

    # packed executables often show a tiny .text next to a huge high-entropy blob
    texts = [s for s in ent if s["name"].lower() in (".text", "CODE", "TEXT")]
    if high and texts and texts[0]["size"] < 0x400:
        score += 10
        flags.append("tiny_text_section")

    # one huge high-entropy section is the classic UPX/themida signature
    if high and high[0]["size"] > 0x8000:
        score += 10
        flags.append("large_high_entropy_blob")

    return {"score": min(score, 100), "flags": flags, "sections": ent}
