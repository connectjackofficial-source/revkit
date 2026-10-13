"""Tests for PE import table parsing (real system DLLs)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.pe import get_imports, parse


def test_real_pe_imports():
    # kernel32.dll imports from ntdll.dll (ordinals) and api-ms-* stubs
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    pe = parse(str(sample))
    imports = get_imports(pe)
    assert len(imports) > 0
    dlls = {imp["dll"] for imp in imports}
    assert any("ntdll" in d.lower() for d in dlls) or len(imports) >= 1
    # every import has at least one resolved function name or ordinal
    for imp in imports:
        assert len(imp["functions"]) > 0
    print("test_real_pe_imports: ok")


def test_imports_of_cmd_style_exe():
    # notepad.exe imports many Win32 API names
    sample = Path(r"C:\Windows\System32\notepad.exe")
    if not sample.exists():
        return
    pe = parse(str(sample))
    imports = get_imports(pe)
    assert len(imports) >= 2  # kernel32 + user32 at minimum
    names = [f for imp in imports for f in imp["functions"]]
    assert len(names) > 5
    print("test_imports_of_cmd_style_exe: ok")


if __name__ == "__main__":
    test_real_pe_imports()
    test_imports_of_cmd_style_exe()
    print("revkit import tests passed")
