"""Single-byte XOR brute force for obfuscated strings/config blobs.

Many packed or obfuscated binaries store strings XORed with one fixed
key byte. We try all 256 keys, score each candidate by how much it
resembles text (printable ratio + English letter frequency), and return
the best candidates.
"""
from __future__ import annotations

from .entropy import shannon_entropy

# Relative letter frequencies for English text, used as a soft prior.
_EN_FREQ = {
    "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7,
    "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3, "l": 4.0, "c": 2.8,
    "u": 2.8, "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0,
    "p": 1.9, "b": 1.5, "v": 1.0, "k": 0.8, "j": 0.15, "x": 0.15,
    "q": 0.10, "z": 0.07,
}


def _text_score(candidate: bytes) -> float:
    """Score 0..100: how text-like is this byte string."""
    if not candidate:
        return 0.0
    n = len(candidate)
    printable = sum(1 for b in candidate
                    if 9 <= b <= 13 or 32 <= b < 127)
    print_ratio = printable / n
    freq = 0.0
    letters = 0
    for b in candidate:
        ch = chr(b).lower()
        if "a" <= ch <= "z":
            letters += 1
            freq += _EN_FREQ.get(ch, 0.0)
    letter_ratio = letters / n
    # heavy penalty for high entropy: a "text" candidate should be
    # low-entropy, obfuscated blobs are near-uniform
    ent = shannon_entropy(candidate)
    entropy_penalty = max(0.0, ent - 4.5)
    score = 0.55 * (print_ratio * 100) + 0.30 * (freq / (letter_ratio * 12.7)
                                                 if letter_ratio else 0.0)
    return max(0.0, score - entropy_penalty * 8.0)


def xor_brute(data: bytes, top: int = 5, min_printable: float = 0.7):
    """Find the most plausible single-byte XOR key for *data*.

    Returns [(key_byte, score, plaintext)] sorted by score descending,
    where plaintext is data XORed with key_byte. Candidates whose
    printable ratio is below *min_printable* are dropped.
    """
    results = []
    for key in range(256):
        plain = bytes(b ^ key for b in data)
        score = _text_score(plain)
        if score > 0:
            results.append((key, round(score, 2), plain))
    results.sort(key=lambda kv: (-kv[1], kv[0]))
    return [(k, s, p) for k, s, p in results if
            sum(1 for b in p if 32 <= b < 127) / len(p) >= min_printable
            ][:top]


def xor_brute_strings(data: bytes, top: int = 5):
    """Brute-force and extract the most text-like XOR-decoded blob.

    Convenience for the common case: find the key, decode, and return
    printable lines. Returns [(key, [strings...])].
    """
    out = []
    for key, _score, plain in xor_brute(data, top=top):
        text = plain.decode("latin-1", errors="replace")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        out.append((key, lines))
    return out
