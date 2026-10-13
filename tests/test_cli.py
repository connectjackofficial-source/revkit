"""Tests for the revkit CLI."""
import contextlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from revkit.cli import main


def _run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


def test_summary():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    code, out = _run([str(sample)])
    assert code == 0
    assert "pe" in out and "x64" in out
    assert "sections:" in out
    print("test_summary: ok")


def test_imports_cli():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    code, out = _run(["--imports", str(sample)])
    assert code == 0
    assert "ntdll" in out.lower()
    print("test_imports_cli: ok")


def test_exports_cli():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    code, out = _run(["--exports", str(sample)])
    assert code == 0
    assert "GetProcAddress" in out
    print("test_exports_cli: ok")


def test_strings_cli():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    code, out = _run(["--strings", "--min-len", "8", str(sample)])
    assert code == 0
    assert "0x" in out and "[ascii]" in out
    print("test_strings_cli: ok")


def test_json_cli():
    sample = Path(r"C:\Windows\System32\kernel32.dll")
    if not sample.exists():
        return
    code, out = _run(["--json", "--sections", str(sample)])
    assert code == 0
    payload = json.loads(out)
    assert payload["format"] == "pe"
    assert payload["detected"]["kind"] == "dll"
    assert len(payload["sections"]) > 0
    print("test_json_cli: ok")


def test_not_pe_cli():
    code, out = _run(["--strings", str(Path(__file__))])
    assert code == 1
    assert "not a PE" in out
    print("test_not_pe_cli: ok")


if __name__ == "__main__":
    test_summary()
    test_imports_cli()
    test_exports_cli()
    test_strings_cli()
    test_json_cli()
    test_not_pe_cli()
    print("revkit CLI tests passed")
