"""Minimal safe ELF parser for Phase 1 metadata."""

from pathlib import Path
from struct import error as StructError
from struct import unpack_from

from igris.analysis.file_intelligence.entropy import slice_entropy
from igris.schemas.file_intelligence import (
    ELFMetadata,
    MetadataValue,
    ProgramHeaderMetadata,
    SectionMetadata,
)

ELF_MACHINES = {
    0x03: "x86",
    0x28: "ARM",
    0x3E: "x86_64",
    0xB7: "ARM64",
    0xF3: "RISC-V",
}

PROGRAM_HEADER_TYPES = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
}


class ELFParseError(ValueError):
    """Raised when an ELF file cannot be parsed safely."""


def parse_elf(path: Path) -> ELFMetadata:
    data = path.read_bytes()
    warnings: list[str] = []
    try:
        if len(data) < 16 or data[:4] != b"\x7fELF":
            raise ELFParseError("missing ELF magic")

        class_value = data[4]
        endian_value = data[5]
        if class_value not in {1, 2}:
            raise ELFParseError(f"unsupported ELF class {class_value}")
        if endian_value not in {1, 2}:
            raise ELFParseError(f"unsupported ELF endianness {endian_value}")

        is_64_bit = class_value == 2
        endian = "<" if endian_value == 1 else ">"
        endianness = "little" if endian_value == 1 else "big"
        min_header = 64 if is_64_bit else 52
        if len(data) < min_header:
            raise ELFParseError("ELF header is truncated")

        machine = _unpack(endian, "H", data, 18)
        entry_point = _unpack(endian, "Q" if is_64_bit else "I", data, 24)
        program_header_offset = _unpack(
            endian, "Q" if is_64_bit else "I", data, 32 if is_64_bit else 28
        )
        section_header_offset = _unpack(
            endian, "Q" if is_64_bit else "I", data, 40 if is_64_bit else 32
        )
        program_header_entry_size = _unpack(endian, "H", data, 54 if is_64_bit else 42)
        program_header_count = _unpack(endian, "H", data, 56 if is_64_bit else 44)
        section_header_entry_size = _unpack(endian, "H", data, 58 if is_64_bit else 46)
        section_header_count = _unpack(endian, "H", data, 60 if is_64_bit else 48)
        section_name_index = _unpack(endian, "H", data, 62 if is_64_bit else 50)

        sections = _parse_sections(
            data=data,
            path=path,
            endian=endian,
            is_64_bit=is_64_bit,
            section_header_offset=section_header_offset,
            section_header_entry_size=section_header_entry_size,
            section_header_count=section_header_count,
            section_name_index=section_name_index,
            warnings=warnings,
        )
        program_headers = _parse_program_headers(
            data=data,
            endian=endian,
            is_64_bit=is_64_bit,
            program_header_offset=program_header_offset,
            program_header_entry_size=program_header_entry_size,
            program_header_count=program_header_count,
            warnings=warnings,
        )

        return ELFMetadata(
            elf_class="ELF64" if is_64_bit else "ELF32",
            architecture=ELF_MACHINES.get(machine, f"unknown_0x{machine:04x}"),
            endianness=endianness,
            entry_point=MetadataValue.present(entry_point),
            program_headers=program_headers,
            sections=sections,
            dynamic_libraries=[],
            dynamic_libraries_status=MetadataValue.not_present(),
            symbols=[],
            symbols_status=MetadataValue.not_present(),
            parse_warnings=warnings,
        )
    except (ELFParseError, StructError, IndexError) as exc:
        raise ELFParseError(str(exc)) from exc


def _parse_sections(
    *,
    data: bytes,
    path: Path,
    endian: str,
    is_64_bit: bool,
    section_header_offset: int,
    section_header_entry_size: int,
    section_header_count: int,
    section_name_index: int,
    warnings: list[str],
) -> list[SectionMetadata]:
    headers: list[dict[str, int]] = []
    for index in range(section_header_count):
        offset = section_header_offset + index * section_header_entry_size
        if offset + section_header_entry_size > len(data):
            warnings.append(f"section {index} header is truncated")
            break

        if is_64_bit:
            name_offset = _unpack(endian, "I", data, offset)
            flags = _unpack(endian, "Q", data, offset + 8)
            address = _unpack(endian, "Q", data, offset + 16)
            raw_offset = _unpack(endian, "Q", data, offset + 24)
            size = _unpack(endian, "Q", data, offset + 32)
        else:
            name_offset = _unpack(endian, "I", data, offset)
            flags = _unpack(endian, "I", data, offset + 8)
            address = _unpack(endian, "I", data, offset + 12)
            raw_offset = _unpack(endian, "I", data, offset + 16)
            size = _unpack(endian, "I", data, offset + 20)

        headers.append(
            {
                "name_offset": name_offset,
                "flags": flags,
                "address": address,
                "raw_offset": raw_offset,
                "size": size,
            }
        )

    names = b""
    if 0 <= section_name_index < len(headers):
        string_header = headers[section_name_index]
        start = string_header["raw_offset"]
        end = start + string_header["size"]
        if end <= len(data):
            names = data[start:end]
        else:
            warnings.append("section name string table is truncated")

    sections: list[SectionMetadata] = []
    for index, header in enumerate(headers):
        name = _read_c_string(names, header["name_offset"]) if names else ""
        size = header["size"]
        raw_offset = header["raw_offset"]
        entropy = None
        if size and raw_offset < len(data):
            readable_size = min(size, len(data) - raw_offset)
            entropy = slice_entropy(path, raw_offset, readable_size)
            if readable_size < size:
                warnings.append(f"section {name or index} data is truncated")

        sections.append(
            SectionMetadata(
                name=name,
                raw_size=size,
                virtual_size=size,
                virtual_address=header["address"],
                raw_offset=raw_offset,
                permissions=_section_permissions(header["flags"]),
                characteristics=f"0x{header['flags']:x}",
                entropy=entropy,
            )
        )
    return sections


def _parse_program_headers(
    *,
    data: bytes,
    endian: str,
    is_64_bit: bool,
    program_header_offset: int,
    program_header_entry_size: int,
    program_header_count: int,
    warnings: list[str],
) -> list[ProgramHeaderMetadata]:
    headers: list[ProgramHeaderMetadata] = []
    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_entry_size
        if offset + program_header_entry_size > len(data):
            warnings.append(f"program header {index} is truncated")
            break

        if is_64_bit:
            header_type = _unpack(endian, "I", data, offset)
            flags = _unpack(endian, "I", data, offset + 4)
            segment_offset = _unpack(endian, "Q", data, offset + 8)
            virtual_address = _unpack(endian, "Q", data, offset + 16)
            file_size = _unpack(endian, "Q", data, offset + 32)
            memory_size = _unpack(endian, "Q", data, offset + 40)
        else:
            header_type = _unpack(endian, "I", data, offset)
            segment_offset = _unpack(endian, "I", data, offset + 4)
            virtual_address = _unpack(endian, "I", data, offset + 8)
            file_size = _unpack(endian, "I", data, offset + 16)
            memory_size = _unpack(endian, "I", data, offset + 20)
            flags = _unpack(endian, "I", data, offset + 24)

        headers.append(
            ProgramHeaderMetadata(
                header_type=PROGRAM_HEADER_TYPES.get(header_type, f"0x{header_type:x}"),
                offset=segment_offset,
                virtual_address=virtual_address,
                file_size=file_size,
                memory_size=memory_size,
                permissions=_program_permissions(flags),
            )
        )
    return headers


def _section_permissions(flags: int) -> str:
    return "".join(
        (
            "W" if flags & 0x1 else "-",
            "A" if flags & 0x2 else "-",
            "X" if flags & 0x4 else "-",
        )
    )


def _program_permissions(flags: int) -> str:
    return "".join(
        (
            "R" if flags & 0x4 else "-",
            "W" if flags & 0x2 else "-",
            "X" if flags & 0x1 else "-",
        )
    )


def _read_c_string(data: bytes, offset: int) -> str:
    if offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _unpack(endian: str, fmt: str, data: bytes, offset: int) -> int:
    return int(unpack_from(f"{endian}{fmt}", data, offset)[0])
