"""Byte-level distribution analysis for binary triage.

byte_distribution() returns the frequency histogram of byte values and
a compact pseudo-random score: uniform-looking distributions (high
entropy, low max share) suggest encrypted or compressed payloads,
while skewed distributions suggest code or structured data.
"""
from __future__ import annotations

from collections import Counter

from .entropy import shannon_entropy


def byte_distribution(data: bytes, top: int = 16) -> dict:
    """Histogram + randomness heuristics for *data*.

    Returns {"total": n, "distinct": k, "entropy": bits/byte,
    "top": [(byte, count, pct), ...], "random_score": 0-100}.
    """
    if not data:
        return {"total": 0, "distinct": 0, "entropy": 0.0,
                "top": [], "random_score": 0}
    cnt = Counter(data)
    n = len(data)
    top_entries = sorted(cnt.items(), key=lambda p: -p[1])[:top]
    top = [(b, c, round(100.0 * c / n, 2)) for b, c in top_entries]
    e = shannon_entropy(data)
    max_share = 100.0 * max(cnt.values()) / n
    # heuristic: entropy near 8 + no dominant byte => looks random
    score = int(min(100, (e / 8.0) * 60 + max(0, 40 - max_share)))
    return {"total": n, "distinct": len(cnt), "entropy": round(e, 4),
            "top": top, "random_score": score}
