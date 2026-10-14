"""revkit: a zero-dependency reverse-engineering toolkit for binaries.

Parses PE/ELF/Mach-O file headers, extracts sections, imports, exports and
printable strings, and scores entropy to spot packed binaries.
"""
from .pe import PE, parse, from_bytes, get_imports, get_exports
from .detect import detect_type
from .strings import extract_strings
from .entropy import shannon_entropy, packer_score, section_entropies
from .overlay import overlay_info
from .elf import ELF, parse as parse_elf

__version__ = "0.2.0"
__all__ = ["PE", "parse", "from_bytes", "get_imports", "get_exports",
           "detect_type", "extract_strings", "shannon_entropy",
           "packer_score", "section_entropies", "overlay_info",
           "ELF", "parse_elf"]
