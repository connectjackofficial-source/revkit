"""revkit: a zero-dependency reverse-engineering toolkit for binaries.

Parses PE/ELF/Mach-O file headers, extracts sections, imports, exports and
printable strings, and scores entropy to spot packed binaries.
"""
from .pe import PE
from .detect import detect_type
from .strings import extract_strings
from .entropy import shannon_entropy, packer_score

__version__ = "0.1.0"
__all__ = ["PE", "detect_type", "extract_strings", "shannon_entropy",
           "packer_score"]
