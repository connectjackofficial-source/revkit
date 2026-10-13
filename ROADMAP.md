# Roadmap

What comes next for revkit, roughly in order of expected value.

## Short term

- [ ] **ELF support** — program headers, dynamic symbol table and imports
      via `DT_NEEDED` / `DT_SYMTAB`.
- [ ] **Mach-O support** — load commands, `LC_LOAD_DYLIB` imports and
      symbol table.
- [ ] **Rich CLI output** — aligned table rendering for sections and
      imports (no more plain `print`).
- [ ] **`--diff` mode** — compare two binaries section-by-section to spot
      what a patch or a new packer version changed.

## Medium term

- [ ] **Packer database** — signature matching for UPX, Themida, VMProtect,
      ASPack, MPRESS with confidence levels.
- [ ] **PE resource parsing** — version info, manifests, icons (offset +
      size, no GUI rendering).
- [ ] **Overlay / anomaly detection** — data appended past the last section
      (a classic malware-injection signal).
- [ ] **TLS callback enumeration** — entry points that run before `main`.

## Longer term

- [ ] **Disassembly hooks** — keep the parser pure, expose byte slices so
      external engines (capstone-style) can plug in.
- [ ] **Web playground** — drag-and-drop analysis in the browser via Pyodide.
- [ ] **OSS-Fuzz harnesses** — fuzz the parsers with crafted headers.

## Non-goals

- No third-party runtime dependencies.
- No GUI; the CLI and library are the product.
- No unpacking or emulation — detection only.
