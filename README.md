# revkit

Zero-dependency reverse-engineering toolkit for quick binary triage.

`revkit` parses PE headers, sections, imports and exports, extracts
printable strings and scores per-section entropy to flag packed or
encrypted payloads — all with the Python standard library, no third-party
dependencies, no `pefile`, no `capstone`.

```console
$ revkit C:\Windows\System32\kernel32.dll
file:      C:\Windows\System32\kernel32.dll
format:    pe (x64) PE32+
sections:  4
entry:     0x1b7f0
imagebase: 0x180000000
size:      0x6c000
run `revkit <file> --help` for sections/imports/exports/strings/entropy
```

## Why

Malware analysts and CTF players spend a lot of time on the same first
five minutes: *what is this file, what does it import, is it packed?*
That is exactly what `revkit` automates. It is designed to be read, not
feared — every module is a few hundred lines of plain `struct.unpack`.

## Features

- **Format detection** — PE / ELF / Mach-O with architecture and PE subtype
  (`exe` / `dll` / `sys`), works like a mini `file(1)`.
- **PE headers** — DOS, COFF and optional header (PE32 and PE32+), machine
  mapping for x86/x64/ARM/ARM64/RISC-V.
- **Section table** — names, virtual addresses, raw offsets, characteristics
  and RVA → file-offset translation.
- **Imports** — DLL names plus every resolved function name or ordinal
  thunk.
- **Exports** — function names, ordinals and RVAs from the export directory.
- **Strings** — ASCII and UTF-16LE printable runs with file offsets
  (`strings(1)` style, both byte alignments).
- **Entropy** — Shannon entropy per section plus a heuristic packer score
  (UPX sections, high-entropy blobs, tiny `.text`).

## Install

```console
pip install .
# or run straight from the repo
python -m revkit.cli <file>
```

## Usage

```console
# summary
revkit sample.bin

# drill down
revkit sample.bin --sections
revkit sample.bin --imports
revkit sample.bin --exports
revkit sample.bin --strings --min-len 8 --utf16
revkit sample.bin --entropy

# machine-readable
revkit sample.bin --json --imports --sections
```

## Example: triage a packed sample

```console
$ revkit packme.exe --entropy
packer score: 90/100 flags=upx_sections,high_entropy_sections,large_high_entropy_blob
  UPX0       size=  57344 entropy=7.914
  UPX1       size=  53248 entropy=7.987
  .rsrc      size=   1024 entropy=5.412
```

## Project layout

```
revkit/
├── revkit/
│   ├── pe.py       PE headers, sections, imports, exports, RVA mapping
│   ├── detect.py   binary format detection (PE/ELF/Mach-O)
│   ├── strings.py  ASCII / UTF-16 printable string extraction
│   ├── entropy.py  Shannon entropy + packer heuristics
│   └── cli.py      command-line interface
└── tests/          script-style tests, no pytest required
```

## Testing

```console
$env:PYTHONPATH = "."  # PowerShell
python -u tests\test_headers.py
python -u tests\test_sections.py
python -u tests\test_imports.py
python -u tests\test_exports.py
python -u tests\test_strings.py
python -u tests\test_detect.py
python -u tests\test_entropy.py
python -u tests\test_cli.py
```

Tests run against real system binaries (`kernel32.dll`, `notepad.exe`) plus
synthetic images built byte-by-byte, so the parsers are exercised both on
ground truth and on hand-crafted edge cases.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned formats (ELF imports, Mach-O
load commands), a rich CLI table output and a `--diff` mode for comparing
two binaries.

## License

MIT — see [LICENSE](LICENSE).
