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
from .resources import get_resources
from .fuzzyhash import fuzzy_hash, fuzzy_compare
from .bytes import byte_distribution
from .rich import rich_header
from .xor import xor_brute, xor_brute_strings

__version__ = "0.3.0"
__all__ = ["PE", "parse", "from_bytes", "get_imports", "get_exports",
           "detect_type", "extract_strings", "shannon_entropy",
           "packer_score", "section_entropies", "overlay_info",
           "ELF", "parse_elf", "get_resources", "fuzzy_hash",
           "fuzzy_compare", "byte_distribution", "rich_header",
           "xor_brute", "xor_brute_strings"]
