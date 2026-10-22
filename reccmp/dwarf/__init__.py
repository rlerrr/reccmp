"""DWARF debug-info ingestion for non-MSVC toolchains (e.g. GCC/MinGW builds).

This module provides an analysis object compatible with `CvdumpAnalysis` so
that the rest of the reccmp comparison pipeline can ingest debug information
from DWARF sidecar files (`.dbg` files produced by `objcopy
--only-keep-debug`).
"""

from .analysis import DwarfAnalysis, parse_dwarf_file

__all__ = ["DwarfAnalysis", "parse_dwarf_file"]
