from dataclasses import dataclass
from functools import cache
import struct
from itertools import pairwise
from typing import Callable, Iterator
from reccmp.compare.lines import LinesDb
from reccmp.difflib import DiffOpcode
from reccmp.compare.pinned_sequences import SequenceMatcherWithPins
from reccmp.compare.asm.fixes import assert_fixup, find_effective_match
from reccmp.compare.asm.parse import AsmExcerpt, ParseAsm
from reccmp.compare.asm.replacement import (
    create_name_lookup,
)
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.compare.diff import EntityCompareResult, RawDiffOutput
from reccmp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats import Image, PEImage
from reccmp.types import ImageId


def has_asserts(image: Image) -> bool:
    if isinstance(image, PEImage):
        return image.is_debug

    return False


def create_valid_addr_lookup(
    db: EntityDb,
    image_id: ImageId,
    bin_file: Image,
) -> Callable[[int], bool]:
    """
    Function generator for a lookup whether an address from a call is valid
    (either a relocation or pointing to something else we know, like a global variable)
    """
    assert image_id in (ImageId.ORIG, ImageId.RECOMP), "Invalid image id"

    @cache
    def lookup(addr: int) -> bool:
        # Check if in relocation table
        if addr > bin_file.imagebase and bin_file.is_relocated_addr(addr):
            return True

        return db.intersects(image_id, addr)

    return lookup


def create_bin_lookup(bin_file: Image) -> Callable[[int], int | None]:
    """Function generator to read a pointer from the bin file"""

    def lookup(addr: int) -> int | None:
        try:
            (ptr,) = struct.unpack("<L", bin_file.read(addr, 4))
            return ptr
        except (struct.error, InvalidVirtualAddressError, InvalidVirtualReadError):
            return None

    return lookup


@dataclass
class FunctionComparator:
    # pylint: disable=too-many-instance-attributes
    db: EntityDb
    lines_db: LinesDb
    orig_bin: Image
    recomp_bin: Image
    report: ReccmpReportProtocol
    types: CvdumpTypesParser
    is_32bit: bool = True
    use_address_placeholders: bool = False

    def __post_init__(self):
        self.orig_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(self.db, ImageId.ORIG, self.orig_bin),
            name_lookup=create_name_lookup(
                self.db,
                ImageId.ORIG,
                create_bin_lookup(self.orig_bin),
                self.types.get_name_for_offset,
            ),
            is_32bit=self.is_32bit,
            use_address_placeholders=self.use_address_placeholders,
        )
        self.recomp_sanitize = ParseAsm(
            addr_test=create_valid_addr_lookup(
                self.db, ImageId.RECOMP, self.recomp_bin
            ),
            name_lookup=create_name_lookup(
                self.db,
                ImageId.RECOMP,
                create_bin_lookup(self.recomp_bin),
                self.types.get_name_for_offset,
            ),
            is_32bit=self.is_32bit,
            use_address_placeholders=self.use_address_placeholders,
        )

    def _source_ref_of_recomp_addr(self, recomp_addr: int | None) -> str | None:
        if recomp_addr is None:
            return None
        path_line_pair = self.lines_db.find_line_of_recomp_address(recomp_addr)
        if path_line_pair is None:
            return None
        return f"{path_line_pair[0].name}:{path_line_pair[1]}"

    def compare_function(self, match: ReccmpMatch) -> EntityCompareResult:
        # Detect when the recomp function size would cause us to read
        # enough bytes from the original function that we cross into
        # the next annotated function.
        orig_size = match.size(ImageId.ORIG)
        recomp_size = match.size(ImageId.RECOMP)

        if orig_size is None:
            assert recomp_size is not None
            orig_max = match.max_size(ImageId.ORIG)
            if orig_max is not None:
                orig_size = min(orig_max, recomp_size)
            else:
                orig_size = recomp_size

        assert orig_size is not None and recomp_size is not None

        orig_raw = self.orig_bin.read(match.orig_addr, orig_size)
        recomp_raw = self.recomp_bin.read(match.recomp_addr, recomp_size)

        # It's unlikely that a function other than an adjuster thunk would
        # start with a SUB instruction, so alert to a possible wrong
        # annotation here.
        # There's probably a better place to do this, but we're reading
        # the function bytes here already.
        try:
            if orig_raw[0] == 0x2B and recomp_raw[0] != 0x2B:
                self.report(
                    ReccmpEvent.GENERAL_WARNING,
                    match.orig_addr,
                    f"Possible thunk ({match.name})",
                )
        except IndexError:
            pass

        orig_combined = self.orig_sanitize.parse_asm_lines(orig_raw, match.orig_addr)
        recomp_combined = self.recomp_sanitize.parse_asm_lines(
            recomp_raw, match.recomp_addr
        )

        # Check for assert calls only if we expect to find them
        if has_asserts(self.orig_bin):
            assert_fixup(orig_combined)

        if has_asserts(self.recomp_bin):
            assert_fixup(recomp_combined)

        line_annotations = self._collect_line_annotations(recomp_combined)

        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        return self._compare_function_assembly(
            orig_combined,
            recomp_combined,
            split_points,
        )

    @staticmethod
    def _print_recomp_instruction(
        instruction: str, *, source_ref: str | None, is_pinned: bool
    ) -> str:
        match source_ref, is_pinned:
            case None, _:
                # cannot be pinned if it has no source reference
                return instruction
            case source_ref_str, False:
                return f"{instruction} \t({source_ref_str})"
            case source_ref_str, True:
                return f"{instruction} \t({source_ref_str}, pinned)"
            case _:
                # Unreachable, but mypy doesn't understand
                assert False

    def _compare_function_assembly(
        self,
        orig: AsmExcerpt,
        recomp: AsmExcerpt,
        split_points: list[tuple[int, int]],
    ) -> EntityCompareResult:
        # Detach addresses from asm lines for the text diff.
        orig_asm = [x.text for x in orig]
        recomp_asm = [x.text for x in recomp]

        diff = SequenceMatcherWithPins(orig_asm, recomp_asm, split_points)

        if diff.ratio() != 1.0:
            # Check whether we can resolve register swaps which are actually
            # perfect matches modulo compiler entropy.
            is_effective = find_effective_match(
                diff.get_opcodes(), orig_asm, recomp_asm
            )
        else:
            is_effective = False

        base_codes = diff.get_opcodes()
        encoding_mismatch_notes, encoding_mismatch_pairs = (
            self._collect_encoding_mismatch_notes(base_codes, orig, recomp)
        )
        codes = self._inject_encoding_mismatch_opcodes(
            base_codes, encoding_mismatch_pairs
        )

        # Convert the addresses to hex string for the diff output
        orig_for_printing = [
            (hex(line.address) if line.address is not None else "", line.text)
            for line in orig
        ]

        recomp_for_printing = [
            (
                hex(addr) if addr is not None else "",
                self._print_recomp_instruction(
                    instruction + encoding_mismatch_notes.get(line_index, ""),
                    source_ref=self._source_ref_of_recomp_addr(addr),
                    is_pinned=any(
                        recomp_addr == line_index for _, recomp_addr in split_points
                    ),
                ),
            )
            for line_index, line in enumerate(recomp)
            for addr, instruction in [(line.address, line.text)]
        ]

        return EntityCompareResult(
            diff=RawDiffOutput(
                codes=codes,
                orig_inst=orig_for_printing,
                recomp_inst=recomp_for_printing,
            ),
            is_effective_match=is_effective,
            match_ratio=diff.ratio(),
        )

    @staticmethod
    def _inject_encoding_mismatch_opcodes(
        codes: list[DiffOpcode], mismatch_pairs: list[tuple[int, int]]
    ) -> list[DiffOpcode]:
        """Turn encoding-only mismatches inside equal blocks into explicit replace opcodes."""
        if len(mismatch_pairs) == 0:
            return codes

        mismatch_by_orig = dict(mismatch_pairs)
        patched: list[DiffOpcode] = []

        for code, i1, i2, j1, j2 in codes:
            if code != "equal":
                patched.append((code, i1, i2, j1, j2))
                continue

            cursor_orig = i1
            cursor_recomp = j1
            for orig_idx in range(i1, i2):
                recomp_idx = mismatch_by_orig.get(orig_idx)
                if recomp_idx is None:
                    continue

                expected_recomp_idx = j1 + (orig_idx - i1)
                if recomp_idx != expected_recomp_idx:
                    continue

                if cursor_orig < orig_idx:
                    patched.append(
                        (
                            "equal",
                            cursor_orig,
                            orig_idx,
                            cursor_recomp,
                            recomp_idx,
                        )
                    )

                patched.append(
                    (
                        "replace",
                        orig_idx,
                        orig_idx + 1,
                        recomp_idx,
                        recomp_idx + 1,
                    )
                )
                cursor_orig = orig_idx + 1
                cursor_recomp = recomp_idx + 1

            if cursor_orig < i2:
                patched.append(("equal", cursor_orig, i2, cursor_recomp, j2))

        return patched

    @staticmethod
    def _collect_encoding_mismatch_notes(
        codes: list[DiffOpcode], orig_asm: AsmExcerpt, recomp_asm: AsmExcerpt
    ) -> tuple[dict[int, str], list[tuple[int, int]]]:
        """Find "equal" instruction lines that decode the same but use different encodings."""
        notes: dict[int, str] = {}
        mismatch_pairs: list[tuple[int, int]] = []
        for code, i1, i2, j1, j2 in codes:
            if code != "equal":
                continue

            common_length = min(i2 - i1, j2 - j1)
            for i in range(common_length):
                orig_idx = i1 + i
                recomp_idx = j1 + i
                orig_line = orig_asm[orig_idx]
                recomp_line = recomp_asm[recomp_idx]
                if (
                    orig_line.raw_bytes is None
                    or recomp_line.raw_bytes is None
                    or orig_line.raw_bytes == recomp_line.raw_bytes
                    # Ignore anyway if the encoding is the same length
                    # Otherwise gets very noisy if the binaries aren't perfectly aligned!
                    or len(orig_line.raw_bytes) == len(recomp_line.raw_bytes)
                ):
                    continue

                # Only flag when capstone decode matches exactly and raw encoding differs.
                if (
                    orig_line.mnemonic != recomp_line.mnemonic
                    or orig_line.op_str != recomp_line.op_str
                ):
                    continue

                mismatch_pairs.append((orig_idx, recomp_idx))
                notes[recomp_idx] = (
                    f" [enc {orig_line.raw_bytes.hex(' ')} ->"
                    f" {recomp_line.raw_bytes.hex(' ')}]"
                )

        return notes, mismatch_pairs

    def _collect_line_annotations(self, recomp: AsmExcerpt) -> list[ReccmpMatch]:
        """
        Finds all `// LINE:` annotations within the given function
        and drops any whose order is not consistent between original and recomp.
        """
        if len(recomp) == 0:
            return []

        recomp_start_addr = recomp[0].address
        recomp_end_addr = recomp[-1].address
        assert recomp_start_addr is not None and recomp_end_addr is not None
        line_annotations = self.db.get_lines_in_recomp_range(
            recomp_start_addr, recomp_end_addr
        )

        # This is a naive/greedy algorithm to remove the non-monotonous entries.
        # There likely is a "better" way to do this, in the sense that the smallest number
        # of entries is removed.
        line_annotations_monotonous: list[ReccmpMatch] = []
        last_address = 0
        for sync_point in line_annotations:
            if sync_point.recomp_addr > last_address:
                line_annotations_monotonous.append(sync_point)
                last_address = sync_point.recomp_addr
            else:
                self.report(
                    ReccmpEvent.WRONG_ORDER,
                    sync_point.orig_addr,
                    f"Line annotation '{sync_point.name}' is out of order relative to other line annotations.",
                )

        return line_annotations_monotonous

    def _split_code_on_line_annotations(
        self,
        orig_combined: AsmExcerpt,
        recomp_combined: AsmExcerpt,
        line_annotations: list[ReccmpMatch],
    ) -> Iterator[tuple[AsmExcerpt, AsmExcerpt]]:
        """
        For each given `// LINE:` annotation, splits the code into the part before,
        the annotated line, and the part after it.
        """
        split_points = self._compute_split_points(
            orig_combined, recomp_combined, line_annotations
        )

        for (orig_start, recomp_start), (orig_end, recomp_end) in pairwise(
            split_points
        ):
            yield (
                orig_combined[orig_start:orig_end],
                recomp_combined[recomp_start:recomp_end],
            )

    def _compute_split_points(
        self, orig: AsmExcerpt, recomp: AsmExcerpt, line_annotations: list[ReccmpMatch]
    ) -> list[tuple[int, int]]:
        """
        Computes the index pairs into `orig` and `recomp`
        that correspond to the line annotations given in `line_annotations`.
        """
        split_points: list[tuple[int, int]] = []

        for line_annotation in line_annotations:
            orig_split_index = next(
                (
                    i
                    for i, entry in enumerate(orig)
                    if entry.address == line_annotation.orig_addr
                ),
                None,
            )
            if orig_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    line_annotation.orig_addr,
                    "Found no code line corresponding to this original address",
                )
                continue

            recomp_split_index = next(
                (
                    i
                    for i, entry in enumerate(recomp)
                    if entry.address == line_annotation.recomp_addr
                ),
                None,
            )
            if recomp_split_index is None:
                self.report(
                    ReccmpEvent.NO_MATCH,
                    line_annotation.orig_addr,
                    f"Found no code line corresponding to recomp address {hex(line_annotation.recomp_addr)}. Recompilation may fix this problem.",
                )
                continue

            split_points.append((orig_split_index, recomp_split_index))
            split_points.append((orig_split_index + 1, recomp_split_index + 1))

        return split_points
