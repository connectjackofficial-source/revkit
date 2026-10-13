"""Tests for printable-string extraction."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.strings import extract_strings


def test_ascii_extraction():
    blob = b"\x00prefix\x00hello world\x00suffix\x00"
    hits = extract_strings(blob, min_length=4, mode="ascii")
    texts = [h["text"] for h in hits]
    assert "hello world" in texts
    assert "prefix" in texts
    assert all(h["encoding"] == "ascii" for h in hits)
    print("test_ascii_extraction: ok")


def test_min_length_filter():
    blob = b"ab\x00abcdef\x00\x00xyz"
    hits = extract_strings(blob, min_length=4, mode="ascii")
    texts = [h["text"] for h in hits]
    assert "abcdef" in texts
    assert "ab" not in texts
    assert "xyz" not in texts  # len 3 < 4
    print("test_min_length_filter: ok")


def test_utf16_extraction():
    blob = b"\x00" * 4 + "welcome".encode("utf-16le") + b"\x00\x00"
    hits = extract_strings(blob, min_length=4, mode="utf16")
    assert any(h["text"] == "welcome" and h["encoding"] == "utf-16le"
               for h in hits)
    print("test_utf16_extraction: ok")


def test_both_modes():
    blob = b"ascii-hit\x00\x00" + "utf16-hit".encode("utf-16le")
    hits = extract_strings(blob, min_length=4, mode="both")
    encs = {h["encoding"] for h in hits}
    assert "ascii" in encs and "utf-16le" in encs
    print("test_both_modes: ok")


def test_real_pe_strings():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    hits = extract_strings(sample.read_bytes(), min_length=5, mode="ascii")
    assert len(hits) > 20
    print("test_real_pe_strings: ok")


if __name__ == "__main__":
    test_ascii_extraction()
    test_min_length_filter()
    test_utf16_extraction()
    test_both_modes()
    test_real_pe_strings()
    print("revkit strings tests passed")
