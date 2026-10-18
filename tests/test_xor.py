"""Tests for revkit batch 3: single-byte XOR brute force."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.xor import xor_brute, xor_brute_strings


def test_xor_brute_recovers_key():
    plain = b"flag{obfuscated_secret_config_key}"
    data = bytes(b ^ 0x2A for b in plain)
    hits = xor_brute(data, top=3)
    assert hits[0][0] == 0x2A, hits
    assert hits[0][2] == plain
    print("test_xor_brute_recovers_key: ok")


def test_xor_brute_drops_garbage():
    data = bytes([0xFF, 0x00, 0x11, 0xEE])  # no text under any single key
    hits = xor_brute(data, top=5)
    assert hits == [], hits
    print("test_xor_brute_drops_garbage: ok")


def test_xor_brute_strings_splits_lines():
    plain = b"user=admin\npass=s3cret\n"
    data = bytes(b ^ 0x11 for b in plain)
    out = xor_brute_strings(data, top=3)
    # key 0x11 (or 0x00 = identity) must decode to the two config lines
    assert any(k == 0x11 and lines == ["user=admin", "pass=s3cret"]
               for k, lines in out), out
    print("test_xor_brute_strings_splits_lines: ok")


if __name__ == "__main__":
    test_xor_brute_recovers_key()
    test_xor_brute_drops_garbage()
    test_xor_brute_strings_splits_lines()
    print("revkit batch3 tests passed")
