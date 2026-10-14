"""revkit command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

from .detect import detect_type
from .entropy import packer_score, section_entropies
from .overlay import overlay_info
from .pe import NotPE, get_exports, get_imports, parse
from .strings import extract_strings


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="revkit",
        description="Zero-dependency reverse-engineering toolkit: PE "
                    "headers, imports, exports, strings and entropy.")
    ap.add_argument("file", help="binary file to analyze")
    ap.add_argument("--imports", action="store_true",
                    help="list imported DLLs and functions")
    ap.add_argument("--exports", action="store_true",
                    help="list exported functions")
    ap.add_argument("--sections", action="store_true",
                    help="list section table")
    ap.add_argument("--strings", action="store_true",
                    help="extract printable strings")
    ap.add_argument("--min-len", type=int, default=4,
                    help="minimum string length (default 4)")
    ap.add_argument("--utf16", action="store_true",
                    help="include UTF-16LE strings")
    ap.add_argument("--entropy", action="store_true",
                    help="per-section entropy and packer heuristics")
    ap.add_argument("--overlay", action="store_true",
                    help="detect data appended past the last section")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = open(args.file, "rb").read()
        pe = parse(args.file)
    except NotPE as exc:
        # still run generic tools (strings/entropy) on non-PE files
        data = open(args.file, "rb").read()
        info = detect_type(data)
        if args.json:
            print(json.dumps({"error": str(exc),
                              "detected": info}, indent=2))
        else:
            print(f"revkit: {args.file}: not a PE ({exc})")
            print(f"format: {info['format']} arch={info['arch']} "
                  f"bits={info['bits']}")
        return 1

    mode = (args.imports or args.exports or args.sections
            or args.strings or args.entropy or args.overlay)
    if args.json:
        _emit_json(args, pe, data)
    elif mode:
        _emit_human(args, pe, data)
    else:
        _emit_summary(args, pe)
    return 0


def _emit_summary(args, pe):
    print(f"file:      {args.file}")
    print(f"format:    pe ({pe.coff.machine_name}) "
          f"{'PE32+' if pe.optional.is_pe32_plus else 'PE32'}")
    print(f"sections:  {len(pe.sections)}")
    print(f"entry:     0x{pe.optional.address_of_entry_point:x}")
    print(f"imagebase: 0x{pe.optional.image_base:x}")
    print(f"size:      0x{pe.optional.size_of_image:x}")
    print("run `revkit <file> --help` for sections/imports/exports/"
          "strings/entropy")


def _emit_human(args, pe, data):
    if args.imports:
        for imp in get_imports(pe):
            print(imp["dll"])
            for f in imp["functions"]:
                print(f"  {f}")
    if args.exports:
        info = get_exports(pe)
        print(f"{info['dll']} (base {info['base']})")
        for e in info["exports"]:
            print(f"  {e['ordinal']}: {e['name']} @ 0x{e['rva']:x}")
    if args.sections:
        for s in pe.sections:
            print(f"{s.name:<10} va=0x{s.virtual_address:06x} "
                  f"vsize=0x{s.virtual_size:06x} "
                  f"raw=0x{s.pointer_to_raw_data:06x} "
                  f"rawsize=0x{s.size_of_raw_data:06x} "
                  f"chars=0x{s.characteristics:08x}")
    if args.strings:
        mode = "both" if args.utf16 else "ascii"
        for h in extract_strings(data, min_length=args.min_len, mode=mode):
            print(f"0x{h['offset']:08x} [{h['encoding']}] {h['text']}")
    if args.entropy:
        info = packer_score(pe)
        print(f"packer score: {info['score']}/100 "
              f"flags={','.join(info['flags']) or 'clean'}")
        for s in info["sections"]:
            print(f"  {s['name']:<10} size={s['size']:>8} "
                  f"entropy={s['entropy']:.3f}")
    if args.overlay:
        info = overlay_info(pe)
        print(f"overlay: {'present' if info['present'] else 'clean'} "
              f"offset=0x{info['offset']:x} size={info['size']} "
              f"entropy_hint={info['entropy_hint']}")


def _emit_json(args, pe, data):
    out = {
        "file": args.file,
        "format": "pe",
        "machine": pe.coff.machine_name,
        "pe32_plus": pe.optional.is_pe32_plus,
        "sections": [s.__dict__ for s in pe.sections],
        "detected": detect_type(data),
    }
    if args.imports:
        out["imports"] = get_imports(pe)
    if args.exports:
        out["exports"] = get_exports(pe)
    if args.strings:
        mode = "both" if args.utf16 else "ascii"
        out["strings"] = extract_strings(data, min_length=args.min_len,
                                         mode=mode)
    if args.entropy:
        out["packer"] = packer_score(pe)
    if args.overlay:
        out["overlay"] = overlay_info(pe)
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
