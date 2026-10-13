"""Printable-string extraction: the workhorse of quick triage.

Finds ASCII and UTF-16LE runs of printable characters, the same heuristic
`strings(1)` uses, with offsets so callers can map hits back into sections.
"""
from __future__ import annotations

_PRINTABLE = frozenset(
    bytes(range(0x20, 0x7F)) + b"\t\n\r\x0b\x0c")


def _ascii_runs(data: bytes, min_length: int):
    run_start = None
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None:
                n = i - run_start
                if n >= min_length:
                    yield run_start, data[run_start:i]
                run_start = None
    if run_start is not None and len(data) - run_start >= min_length:
        yield run_start, data[run_start:]


def _utf16_runs(data: bytes, min_length: int):
    # Scan both byte alignments: UTF-16 data can start on any offset.
    seen = set()
    for align in (0, 1):
        run_start = None
        for i in range(align, len(data) - 1, 2):
            lo, hi = data[i], data[i + 1]
            if hi == 0 and 0x20 <= lo < 0x7F:
                if run_start is None:
                    run_start = i
            else:
                if run_start is not None:
                    n = (i - run_start) // 2
                    if n >= min_length and run_start not in seen:
                        seen.add(run_start)
                        yield run_start, data[run_start:i].decode(
                            "utf-16le", "replace")
                    run_start = None
        if run_start is not None:
            n = (len(data) - run_start) // 2
            if n >= min_length and run_start not in seen:
                seen.add(run_start)
                yield run_start, data[run_start:].decode("utf-16le", "replace")


def extract_strings(data: bytes, min_length: int = 4,
                    mode: str = "both") -> list:
    """Extract printable strings from a byte buffer.

    mode: "ascii" | "utf16" | "both". Returns a list of
    {"offset": int, "text": str, "encoding": str}.
    """
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    hits = []
    if mode in ("ascii", "both"):
        for off, raw in _ascii_runs(data, min_length):
            hits.append({"offset": off, "text": raw.decode("ascii"),
                         "encoding": "ascii"})
    if mode in ("utf16", "both"):
        for off, text in _utf16_runs(data, min_length):
            hits.append({"offset": off, "text": text, "encoding": "utf-16le"})
    return hits
