"""Minimal safe PE parser for Phase 1 metadata."""

from pathlib import Path
from struct import error as StructError
from struct import unpack_from

from igris.analysis.file_intelligence.entropy import slice_entropy
from igris.schemas.file_intelligence import (
    FieldState,
    MetadataValue,
    PEDataDirectoryStatus,
    PEMetadata,
    SectionMetadata,
)

MACHINE_TYPES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    7: "posix_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    14: "xbox",
    16: "windows_boot_application",
}


class PEParseError(ValueError):
    """Raised when a PE file cannot be parsed safely."""


def parse_pe(path: Path) -> PEMetadata:
    data = path.read_bytes()
    warnings: list[str] = []

    try:
        if len(data) < 64 or data[:2] != b"MZ":
            raise PEParseError("missing DOS MZ header")
        pe_offset = _u32(data, 0x3C)
        if pe_offset + 24 > len(data):
            raise PEParseError("PE header offset points outside file")
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PEParseError("missing PE signature")

        coff_offset = pe_offset + 4
        machine = _u16(data, coff_offset)
        number_of_sections = _u16(data, coff_offset + 2)
        timestamp = _u32(data, coff_offset + 4)
        symbol_table_pointer = _u32(data, coff_offset + 8)
        number_of_symbols = _u32(data, coff_offset + 12)
        optional_header_size = _u16(data, coff_offset + 16)
        characteristics = _u16(data, coff_offset + 18)

        optional_offset = coff_offset + 20
        if optional_header_size < 2 or optional_offset + optional_header_size > len(data):
            raise PEParseError("optional header is missing or truncated")
        optional_magic = _u16(data, optional_offset)
        if optional_magic == 0x10B:
            pe_type = "PE32"
            image_base = _u32(data, optional_offset + 28)
            data_directory_offset = optional_offset + 96
        elif optional_magic == 0x20B:
            pe_type = "PE32+"
            image_base = _u64(data, optional_offset + 24)
            data_directory_offset = optional_offset + 112
        else:
            raise PEParseError(f"unsupported PE optional header magic 0x{optional_magic:x}")

        address_of_entry_point = _u32(data, optional_offset + 16)
        section_alignment = _u32(data, optional_offset + 32)
        file_alignment = _u32(data, optional_offset + 36)
        size_of_image = _u32(data, optional_offset + 56)
        subsystem_value = _u16(data, optional_offset + 68)
        number_of_rva_and_sizes = (
            _u32(data, data_directory_offset - 4)
            if data_directory_offset - 4 + 4 <= optional_offset + optional_header_size
            else 0
        )

        section_table_offset = optional_offset + optional_header_size
        sections = _parse_sections(
            data=data,
            path=path,
            section_table_offset=section_table_offset,
            number_of_sections=number_of_sections,
            warnings=warnings,
        )

        imports_status = PEDataDirectoryStatus(state=FieldState.NOT_PRESENT)
        exports_status = PEDataDirectoryStatus(state=FieldState.NOT_PRESENT)
        resources_status = PEDataDirectoryStatus(state=FieldState.NOT_PRESENT)

        if number_of_rva_and_sizes:
            exports_status, imports_status, resources_status = _directory_statuses(
                data=data,
                optional_offset=optional_offset,
                optional_header_size=optional_header_size,
                data_directory_offset=data_directory_offset,
            )

        return PEMetadata(
            dos_magic="MZ",
            pe_signature="PE\\0\\0",
            machine=f"0x{machine:04x}",
            coff_header={
                "machine": f"0x{machine:04x}",
                "number_of_sections": number_of_sections,
                "timestamp": timestamp,
                "symbol_table_pointer": symbol_table_pointer,
                "number_of_symbols": number_of_symbols,
                "optional_header_size": optional_header_size,
                "characteristics": f"0x{characteristics:04x}",
            },
            optional_header={
                "type": pe_type,
                "address_of_entry_point": address_of_entry_point,
                "image_base": image_base,
                "section_alignment": section_alignment,
                "file_alignment": file_alignment,
                "size_of_image": size_of_image,
                "subsystem": subsystem_value,
            },
            architecture=MACHINE_TYPES.get(machine, f"unknown_0x{machine:04x}"),
            image_base=image_base,
            entry_point=MetadataValue.present(address_of_entry_point),
            subsystem=SUBSYSTEMS.get(subsystem_value, f"unknown_{subsystem_value}"),
            number_of_sections=number_of_sections,
            sections=sections,
            imports=[],
            imports_status=imports_status,
            exports=[],
            exports_status=exports_status,
            resources=[],
            resources_status=resources_status,
            parse_warnings=warnings,
        )
    except (PEParseError, StructError, IndexError) as exc:
        raise PEParseError(str(exc)) from exc


def _parse_sections(
    *,
    data: bytes,
    path: Path,
    section_table_offset: int,
    number_of_sections: int,
    warnings: list[str],
) -> list[SectionMetadata]:
    sections: list[SectionMetadata] = []
    for index in range(number_of_sections):
        offset = section_table_offset + index * 40
        if offset + 40 > len(data):
            warnings.append(f"section {index} header is truncated")
            break

        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("utf-8", errors="replace")
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_offset = _u32(data, offset + 20)
        characteristics = _u32(data, offset + 36)
        entropy = None
        if raw_size and raw_offset < len(data):
            readable_size = min(raw_size, len(data) - raw_offset)
            entropy = slice_entropy(path, raw_offset, readable_size)
            if readable_size < raw_size:
                warnings.append(f"section {name or index} raw data is truncated")

        sections.append(
            SectionMetadata(
                name=name,
                virtual_size=virtual_size,
                raw_size=raw_size,
                virtual_address=virtual_address,
                raw_offset=raw_offset,
                characteristics=f"0x{characteristics:08x}",
                entropy=entropy,
            )
        )
    return sections


def _directory_statuses(
    *,
    data: bytes,
    optional_offset: int,
    optional_header_size: int,
    data_directory_offset: int,
) -> tuple[PEDataDirectoryStatus, PEDataDirectoryStatus, PEDataDirectoryStatus]:
    statuses: list[PEDataDirectoryStatus] = []
    optional_end = optional_offset + optional_header_size
    for directory_index in (0, 1, 2):
        directory_offset = data_directory_offset + directory_index * 8
        if directory_offset + 8 > optional_end or directory_offset + 8 > len(data):
            statuses.append(PEDataDirectoryStatus(state=FieldState.FAILED, error="truncated"))
            continue
        rva = _u32(data, directory_offset)
        size = _u32(data, directory_offset + 4)
        statuses.append(
            PEDataDirectoryStatus(
                state=FieldState.PRESENT if rva and size else FieldState.NOT_PRESENT
            )
        )
    exports_status, imports_status, resources_status = statuses
    return exports_status, imports_status, resources_status


def _u16(data: bytes, offset: int) -> int:
    return int(unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(unpack_from("<I", data, offset)[0])


def _u64(data: bytes, offset: int) -> int:
    return int(unpack_from("<Q", data, offset)[0])
