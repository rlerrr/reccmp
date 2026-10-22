"""Extract `.debug_*` sections from a PE-COFF sidecar file and wrap them in a
synthetic in-memory ELF32 file so they can be parsed with pyelftools.

pyelftools only parses DWARF from ELF/Mach-O containers, but MinGW-built
Windows binaries keep their DWARF sections in the PE-COFF sidecar produced by
`objcopy --only-keep-debug`. The DWARF payload itself is container-agnostic,
so relocating the `.debug_*` sections into a minimal synthetic ELF lets the
existing pyelftools machinery do the heavy lifting.
"""

import io
import struct

from elftools.elf.elffile import ELFFile

ELF32_EHDR_SIZE = 52
ELF32_SHDR_SIZE = 40


def extract_debug_sections(data: bytes) -> list[tuple[str, bytes]]:
    """Parse the COFF section table of a PE/OBJ file and return the raw
    contents of every `.debug_*` section as `(name, content)` tuples.

    Long section names (`/N` string-table references) are resolved.
    """
    # Locate headers. For PE files the COFF header follows the DOS stub;
    # find e_lfanew -> "PE\0\0" -> COFF header. For plain COFF objects we
    # start at offset 0.
    header_offset = 0
    if data[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        header_offset = e_lfanew + 4

    num_sections = struct.unpack_from("<H", data, header_offset + 2)[0]
    optional_size = struct.unpack_from("<H", data, header_offset + 16)[0]
    section_table = header_offset + 20 + optional_size

    # In COFF/PE, the string table follows the symbol table.
    symtab_ptr = struct.unpack_from("<I", data, header_offset + 8)[0]
    num_symbols = struct.unpack_from("<I", data, header_offset + 12)[0]
    string_table_offset = symtab_ptr + num_symbols * 18
    if string_table_offset < len(data):
        string_table_size = struct.unpack_from("<I", data, string_table_offset)[0]
        string_table = data[string_table_offset:string_table_offset + string_table_size]
    else:
        string_table = b"\x00"

    sections = []
    for i in range(num_sections):
        entry = section_table + i * 40
        raw_name = data[entry:entry + 8]
        virtual_size = struct.unpack_from("<I", data, entry + 8)[0]
        size_of_raw_data = struct.unpack_from("<I", data, entry + 16)[0]
        pointer_to_raw_data = struct.unpack_from("<I", data, entry + 20)[0]

        name = raw_name.rstrip(b"\0").decode("latin-1")
        if name.startswith("/"):
            string_offset = int(name[1:])
            name = _read_string_at(string_table, string_offset)

        if not name.startswith(".debug"):
            continue

        size = virtual_size or size_of_raw_data
        if size == 0 or pointer_to_raw_data == 0:
            continue

        content = data[pointer_to_raw_data:pointer_to_raw_data + size]
        if len(content) < size:
            # Padded/over-long virtual sizes can read past EOF; tolerate this.
            content = content.ljust(size, b"\0")
        sections.append((name, content))

    return sections


def build_synthetic_elf(debug_sections: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal in-memory ELF32 ET_EXEC image containing just the given
    `(name, content)` debug sections."""
    names = [b"\x00"]
    name_offsets = {}
    pos = 1
    for nm, _content in debug_sections:
        name_offsets[nm] = pos
        enc = nm.encode("latin-1") + b"\x00"
        names.append(enc)
        pos += len(enc)
    name_offsets[".shstrtab"] = pos
    names.append(b".shstrtab\x00")
    shstrtab = b"".join(names)

    num_sections = len(debug_sections) + 2
    shstrndx = num_sections - 1

    body = bytearray()
    section_offsets = {}
    cur = ELF32_EHDR_SIZE
    for nm, content in debug_sections:
        section_offsets[nm] = cur
        body += content
        cur += len(content)

    shstr_offset = cur
    body += shstrtab
    cur += len(shstrtab)
    shoff = cur

    ident = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\x00" * 7
    ehdr = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,  # e_type: ET_EXEC
        3,  # e_machine: EM_386
        1,  # e_version
        0,  # e_entry
        0,  # e_phoff
        shoff,
        0,  # e_flags
        ELF32_EHDR_SIZE,
        0,  # e_phentsize
        0,  # e_phnum
        ELF32_SHDR_SIZE,
        num_sections,
        shstrndx,
    )

    section_rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for nm, content in debug_sections:
        section_rows.append(
            (name_offsets[nm], 1, 0, 0, section_offsets[nm], len(content), 0, 0, 1, 0)
        )
    section_rows.append(
        (name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0)
    )
    sh_table = b"".join(struct.pack("<10I", *row) for row in section_rows)

    return ehdr + bytes(body) + sh_table


def load_debug_sections_from_file(path) -> ELFFile:
    """Open a COFF/PE sidecar, relocate its DWARF sections into a synthetic
    ELF and return a pyelftools ELFFile over it."""
    from pathlib import Path

    data = Path(path).read_bytes()
    return ELFFile(io.BytesIO(build_synthetic_elf(extract_debug_sections(data))))


def _read_string_at(table: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(table):
        return ""
    end = table.find(b"\0", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("latin-1")
