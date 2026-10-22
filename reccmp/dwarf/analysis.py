"""Build a CvdumpAnalysis-compatible symbol/line analysis from DWARF data."""

import io
import logging
import struct
from pathlib import Path, PureWindowsPath

from elftools.elf.elffile import ELFFile

from reccmp.cvdump.analysis import CvdumpNode
from reccmp.cvdump.parser import LineValue
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.formats.pe import PEImage
from reccmp.types import EntityType

from .container import build_synthetic_elf, extract_debug_sections

logger = logging.getLogger(__name__)

# DW_FORM classes for DW_AT_high_pc:
# - class "address" (DW_FORM_addr etc.) gives an absolute address
# - class "constant" (DW_FORM_data*, DW_FORM_sdata...) gives an offset from low_pc
_ADDRESS_FORMS = frozenset(("DW_FORM_addr", "DW_FORM_addrx"))


def parse_dwarf_file(path, recomp_bin: PEImage) -> "DwarfAnalysis":
    """Read a COFF/PE debug sidecar (`.dbg`) and produce a DwarfAnalysis.

    `recomp_bin` is the PEImage of the companion binary. DWARF addresses are
    absolute virtual addresses in that same address space, so it is used to
    validate addresses and convert them into the (section, offset) pairs
    that reccmp uses internally.
    """
    data = Path(path).read_bytes()
    elf = ELFFile(io.BytesIO(build_synthetic_elf(extract_debug_sections(data))))
    return DwarfAnalysis(elf, recomp_bin)


def _cu_offsets(debug_info: bytes):
    """Walk compile-unit offsets in the .debug_info section.

    We cannot use `DWARFInfo.iter_CUs()` because GCC leaves zero padding
    after the last unit, which desynchronizes that iterator.
    """
    offset = 0
    size = len(debug_info)
    while offset < size:
        unit_length = struct.unpack_from("<I", debug_info, offset)[0]
        if unit_length in (0, 0xFFFFFFFF):
            break
        yield offset
        offset += unit_length + 4


def _decode_name(value) -> str | None:
    if value is None:
        return None
    try:
        return bytes(value).decode("latin-1")
    except (ValueError, TypeError):
        return None


def _function_size(die, low_pc: int) -> int | None:
    attr = die.attributes.get("DW_AT_high_pc")
    if attr is None or not isinstance(attr.value, int):
        return None
    if attr.form in _ADDRESS_FORMS:
        return int(attr.value) - low_pc
    return int(attr.value)


class DwarfAnalysis:
    """Symbol and line analysis from DWARF debug info.

    Provides the same interface as `CvdumpAnalysis`:
    - `nodes`: list of `CvdumpNode` with address bounds for functions
    - `lines`: dict of filename -> list of LineValue (line number, section, offset)
    - `types`: (empty) CvdumpTypesParser
    - `truncate_symbols`: always False
    """

    def __init__(self, elf: ELFFile, recomp_bin: PEImage):
        self.elf = elf
        self.recomp_bin = recomp_bin
        self.dwarf = elf.get_dwarf_info()
        self.types = CvdumpTypesParser()
        self.truncate_symbols = False

        debug_info = elf.get_section_by_name(".debug_info")
        if debug_info is None:
            raise ValueError("No .debug_info section in debug sidecar")
        debug_info_bytes = debug_info.data()

        self.nodes: list[CvdumpNode] = []
        self.lines: dict[PureWindowsPath, list[LineValue]] = {}

        cus = []
        for offset in _cu_offsets(debug_info_bytes):
            try:
                cus.append(self.dwarf.get_CU_at(offset))
            except Exception:  # pylint: disable=broad-except
                logger.debug("Failed to parse CU at 0x%x", offset, exc_info=True)

        for cu in cus:
            self._add_functions_from_cu(cu)
        self.nodes.sort(key=lambda n: (n.section, n.offset))

        for cu in cus:
            self._add_lines_from_cu(cu)
        for path in self.lines:
            self.lines[path].sort(key=lambda v: (v.offset, v.line_number))

    def _va_to_section_offset(self, va: int) -> tuple[int, int] | None:
        try:
            return self.recomp_bin.get_relative_addr(va)
        except Exception:  # pylint: disable=broad-except
            return None

    def _add_functions_from_cu(self, cu):
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram" or die.is_null():
                continue
            low_attr = die.attributes.get("DW_AT_low_pc")
            if low_attr is None or not isinstance(low_attr.value, int):
                continue
            low_pc = int(low_attr.value)
            size = _function_size(die, low_pc)
            if size is None:
                continue

            section_offset = self._va_to_section_offset(low_pc)
            if section_offset is None:
                continue
            section, offset = section_offset

            name = _decode_name(self._resolve_attribute(die, "DW_AT_name"))
            if name is None:
                continue

            node = CvdumpNode(
                section=section,
                offset=offset,
                friendly_name=name,
                node_type=EntityType.FUNCTION,
                confirmed_size=size,
            )
            linkage = _decode_name(self._resolve_attribute(die, "DW_AT_linkage_name"))
            if linkage is None:
                linkage = _decode_name(
                    self._resolve_attribute(die, "DW_AT_MIPS_linkage_name")
                )
            if linkage is not None and linkage != name:
                node.decorated_name = linkage

            self.nodes.append(node)

    def _resolve_attribute(self, die, attr_name: str, depth: int = 0):
        """Resolve an attribute, potentially through DW_AT_specification or
        DW_AT_abstract_origin references."""
        attr = die.attributes.get(attr_name)
        if attr is not None:
            return attr.value

        if depth > 8:
            return None

        for ref_name in ("DW_AT_specification", "DW_AT_abstract_origin"):
            if die.attributes.get(ref_name) is not None:
                try:
                    ref_die = die.get_DIE_from_attribute(ref_name)
                except Exception:  # pylint: disable=broad-except
                    logger.debug(
                        "Failed to resolve %s reference",
                        ref_name,
                        exc_info=True,
                    )
                    return None
                return self._resolve_attribute(ref_die, attr_name, depth + 1)

        return None

    def _add_lines_from_cu(self, cu):
        """Populate `self.lines` from the CU's .debug_line line program."""
        line_program = self.dwarf.line_program_for_CU(cu)
        if line_program is None:
            return

        header = line_program.header
        include_dirs = list(header.include_directory)
        comp_dir = self._cu_comp_dir(cu)

        for entry in line_program.get_entries():
            state = entry.state
            if state is None or state.line is None:
                continue
            # Rows with an address of zero (or an end_sequence row) are best
            # filtered out here. In practice pyelftools sets state.address to
            # None for end_sequence entries only when the state is None, so we
            # just guard the low values.
            if state.address in (0, -1):
                continue
            if self._va_to_section_offset(state.address) is None:
                continue

            path = self._line_file_path(
                comp_dir, include_dirs, header.file_entry, state.file
            )
            if path is None:
                continue

            section, offset = self._va_to_section_offset(state.address)
            self.lines.setdefault(path, []).append(
                LineValue(int(state.line), section, offset)
            )

    def _cu_comp_dir(self, cu) -> str | None:
        top_die = cu.get_top_DIE()
        attr = top_die.attributes.get("DW_AT_comp_dir")
        if attr is not None:
            return _decode_name(attr.value)
        return None

    def _line_file_path(self, comp_dir, include_dirs, file_entries, file_index):
        """Resolve a (1-based) line-table file index into a path."""
        # Index into file_entries: 1-based per DWARF >= 3 convention.
        if file_index == 0 or file_index > len(file_entries):
            return None
        file_entry = file_entries[file_index - 1]
        filename = _decode_name(file_entry.name)
        if filename is None:
            return None

        dir_index = file_entry.dir_index
        if dir_index == 0:
            directory = comp_dir
        elif dir_index <= len(include_dirs):
            directory = _decode_name(include_dirs[dir_index - 1])
        else:
            directory = None

        if directory:
            return PureWindowsPath(f"{directory}/{filename}")
        return PureWindowsPath(filename)
