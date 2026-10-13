"""Tests for PE export table parsing (real system DLLs)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.pe import get_exports, parse


def test_kernel32_exports():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = parse(str(sample))
    info = get_exports(pe)
    assert info["dll"].lower().endswith("kernel32.dll")
    assert len(info["exports"]) > 100  # kernel32 exports hundreds of APIs
    names = {e["name"] for e in info["exports"]}
    assert "GetProcAddress" in names
    assert "VirtualAlloc" in names
    assert "CreateFileW" in names
    # ordinals are monotonically increasing from base
    ords = [e["ordinal"] for e in info["exports"]]
    assert ords == sorted(ords)
    print("test_kernel32_exports: ok")


def test_exports_fields():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = parse(str(sample))
    info = get_exports(pe)
    first = info["exports"][0]
    assert set(first) == {"name", "ordinal", "rva"}
    assert isinstance(first["rva"], int) and first["rva"] > 0
    assert first["ordinal"] >= info["base"]
    print("test_exports_fields: ok")


if __name__ == "__main__":
    test_kernel32_exports()
    test_exports_fields()
    print("revkit export tests passed")
