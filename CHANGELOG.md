# Changelog

All notable changes to revkit are tracked here.

## [0.3.0] - 2026-10-18

### Added

- `fuzzy_hash()` / `fuzzy_compare()` — ssdeep-style context-triggered
  piecewise hashing for malware/firmware similarity triage
- `byte_distribution()` — byte histogram plus a pseudo-randomness score
  to flag encrypted or compressed payloads
- `rich_header()` — decodes the XOR-obfuscated VS linker Rich header
  (compiler fingerprinting)

## [0.2.0] - 2026-10-14

### Added

- `overlay_info()` — detect data appended past the last section (a classic
  dropper/injector signal), with a coarse entropy hint
- ELF support: `revkit.elf.parse()` reads the ELF header and program header
  table; `--segments` prints PT_* segments
- `get_resources()` — enumerate embedded PE resource types (VERSION,
  MANIFEST, RCDATA, …); `--resources` prints them
- CLI: `--overlay`, `--segments`, `--resources` flags; JSON output includes
  the new sections

## [0.1.0] - 2026-10-13

Initial release.

### Added

- **Format detection** (`detect.py`): PE / ELF / Mach-O classification with
  architecture, bitness and PE subtype (`exe` / `dll` / `sys`).
- **PE header parsing** (`pe.py`): DOS, COFF and optional header for both
  PE32 (`0x10B`) and PE32+ (`0x20B`) images; machine mapping for x86, x64,
  ARM, ARM64, PowerPC and RISC-V.
- **Section table** (`pe.py`): names, virtual addresses/sizes, raw
  offsets/sizes, characteristics and `rva_to_offset()` mapping.
- **Import directory** (`pe.py`): DLL names and function-name/ordinal thunk
  resolution for PE32 and PE32+.
- **Export directory** (`pe.py`): exported names, ordinals and RVAs.
- **String extraction** (`strings.py`): ASCII and UTF-16LE printable runs
  with offsets, both byte alignments, configurable minimum length.
- **Entropy analysis** (`entropy.py`): per-section Shannon entropy and a
  heuristic packer score (UPX sections, high-entropy blobs, tiny `.text`).
- **CLI** (`cli.py`): summary mode, `--sections`, `--imports`, `--exports`,
  `--strings`, `--entropy` and `--json` output.
- **Tests**: script-style suites covering real system binaries and
  byte-by-byte synthetic PE images.

### Notes

- Zero third-party dependencies; everything is `struct` + `collections`.
- Non-PE files still work with `--strings` / `--entropy` (format detection
  reports the actual type).
