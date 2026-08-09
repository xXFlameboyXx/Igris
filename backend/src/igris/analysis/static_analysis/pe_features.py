"""PE-specific static feature extraction without execution."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from struct import error as StructError
from struct import unpack_from
from typing import NamedTuple

from igris.analysis.static_analysis.taxonomy import API_TAXONOMY, categorize_api
from igris.schemas.file_intelligence import HashSet, SectionMetadata
from igris.schemas.static_analysis import (
    ImportCategory,
    NormalizedImport,
    PEStaticFeatures,
    ResourceHashSet,
    StaticResource,
)


@dataclass(frozen=True)
class PESectionRange:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class PEStaticExtraction:
    imports: list[NormalizedImport]
    resources: list[StaticResource]
    features: PEStaticFeatures
    parse_warnings: list[str]


class PELayout(NamedTuple):
    entry_point: int
    directories: dict[int, tuple[int, int]]
    sections: list[PESectionRange]


def extract_pe_static(
    data: bytes, path: Path, sections: list[SectionMetadata]
) -> PEStaticExtraction:
    warnings: list[str] = []
    try:
        layout = _parse_layout(data)
    except (ValueError, StructError, IndexError) as exc:
        return PEStaticExtraction(
            imports=[],
            resources=[],
            features=_fallback_features(sections),
            parse_warnings=[f"PE static feature parse failed: {exc}"],
        )

    import_directory = layout.directories.get(1, (0, 0))
    resource_directory = layout.directories.get(2, (0, 0))
    tls_directory = layout.directories.get(9, (0, 0))
    import_table = _parse_imports(data, layout.sections, import_directory, warnings)
    resources = _parse_resources(path, data, layout.sections, resource_directory, warnings)
    overlay_offset = _overlay_offset(data, layout.sections)
    overlay_size = max(0, len(data) - overlay_offset)
    entry_point_section = _section_name_for_rva(layout.entry_point, layout.sections)
    executable_count = 0
    writable_executable_count = 0
    for section in layout.sections:
        executable = bool(section.characteristics & 0x20000000)
        writable = bool(section.characteristics & 0x80000000)
        if executable:
            executable_count += 1
        if executable and writable:
            writable_executable_count += 1

    features = PEStaticFeatures(
        tls_callbacks_present=bool(tls_directory[0] and tls_directory[1]),
        overlay_present=overlay_size > 0,
        overlay_size=overlay_size,
        import_descriptor_count=len({item.module for item in import_table if item.module}),
        executable_section_count=executable_count,
        writable_executable_section_count=writable_executable_count,
        entry_point_section=entry_point_section,
        suspicious_entry_point_section=_is_suspicious_entry_section(entry_point_section),
    )
    return PEStaticExtraction(import_table, resources, features, warnings)


def api_references_from_strings(values: set[str]) -> list[NormalizedImport]:
    imports: list[NormalizedImport] = []
    seen: set[str] = set()
    for value in sorted(values):
        for api_name, category in API_TAXONOMY.items():
            if api_name not in value or api_name in seen:
                continue
            imports.append(
                NormalizedImport(
                    module=None,
                    name=api_name,
                    category=category,
                    source="string_reference",
                )
            )
            seen.add(api_name)
    return imports


def _parse_layout(data: bytes) -> PELayout:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("missing MZ header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff_offset = pe_offset + 4
    number_of_sections = _u16(data, coff_offset + 2)
    optional_header_size = _u16(data, coff_offset + 16)
    optional_offset = coff_offset + 20
    optional_magic = _u16(data, optional_offset)
    if optional_magic == 0x10B:
        data_directory_offset = optional_offset + 96
    elif optional_magic == 0x20B:
        data_directory_offset = optional_offset + 112
    else:
        raise ValueError(f"unsupported optional header magic 0x{optional_magic:x}")
    optional_end = optional_offset + optional_header_size
    entry_point = _u32(data, optional_offset + 16)
    directories: dict[int, tuple[int, int]] = {}
    for index in range(16):
        offset = data_directory_offset + index * 8
        if offset + 8 <= optional_end and offset + 8 <= len(data):
            directories[index] = (_u32(data, offset), _u32(data, offset + 4))

    section_table = optional_offset + optional_header_size
    parsed_sections: list[PESectionRange] = []
    for index in range(number_of_sections):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        parsed_sections.append(
            PESectionRange(
                name=name,
                virtual_address=_u32(data, offset + 12),
                virtual_size=_u32(data, offset + 8),
                raw_offset=_u32(data, offset + 20),
                raw_size=_u32(data, offset + 16),
                characteristics=_u32(data, offset + 36),
            )
        )

    return PELayout(entry_point=entry_point, directories=directories, sections=parsed_sections)


def _parse_imports(
    data: bytes,
    sections: list[PESectionRange],
    import_directory: tuple[int, int],
    warnings: list[str],
) -> list[NormalizedImport]:
    rva, size = import_directory
    if not rva or not size:
        return []
    offset = _rva_to_offset(rva, sections)
    if offset is None:
        warnings.append("import directory RVA did not map to a section")
        return []
    imports: list[NormalizedImport] = []
    seen: set[tuple[str, str | int]] = set()
    for descriptor_offset in range(offset, min(offset + size, len(data)), 20):
        if descriptor_offset + 20 > len(data):
            warnings.append("import descriptor table is truncated")
            break
        original_first_thunk = _u32(data, descriptor_offset)
        name_rva = _u32(data, descriptor_offset + 12)
        first_thunk = _u32(data, descriptor_offset + 16)
        if original_first_thunk == name_rva == first_thunk == 0:
            break
        module_offset = _rva_to_offset(name_rva, sections)
        module = _read_c_string(data, module_offset) if module_offset is not None else "unknown"
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(thunk_rva, sections)
        if thunk_offset is None:
            continue
        cursor = thunk_offset
        while cursor + 4 <= len(data):
            thunk = _u32(data, cursor)
            cursor += 4
            if thunk == 0:
                break
            if thunk & 0x80000000:
                ordinal = thunk & 0xFFFF
                ordinal_key = (module, ordinal)
                if ordinal_key not in seen:
                    imports.append(
                        NormalizedImport(
                            module=module,
                            name=f"ordinal_{ordinal}",
                            ordinal=ordinal,
                            category=ImportCategory.OTHER,
                            source="import_table",
                        )
                    )
                    seen.add(ordinal_key)
                continue
            hint_name_offset = _rva_to_offset(thunk, sections)
            if hint_name_offset is None or hint_name_offset + 2 >= len(data):
                continue
            name = _read_c_string(data, hint_name_offset + 2)
            name_key = (module, name)
            if name and name_key not in seen:
                imports.append(
                    NormalizedImport(
                        module=module,
                        name=name,
                        category=categorize_api(name),
                        source="import_table",
                    )
                )
                seen.add(name_key)
    return imports


def _parse_resources(
    path: Path,
    data: bytes,
    sections: list[PESectionRange],
    resource_directory: tuple[int, int],
    warnings: list[str],
) -> list[StaticResource]:
    rva, size = resource_directory
    if not rva or not size:
        return []
    offset = _rva_to_offset(rva, sections)
    if offset is None:
        warnings.append("resource directory RVA did not map to a section")
        return []
    readable = min(size, len(data) - offset)
    if readable <= 0:
        warnings.append("resource directory points outside file")
        return []
    blob_hashes = _hash_slice(path, offset, readable)
    return [
        StaticResource(
            resource_type="pe_resource_directory",
            identifier=None,
            language=None,
            size=readable,
            offset=offset,
            hashes=ResourceHashSet(
                sha256=blob_hashes.sha256,
                sha1=blob_hashes.sha1,
                md5=blob_hashes.md5,
            ),
        )
    ]


def _fallback_features(sections: list[SectionMetadata]) -> PEStaticFeatures:
    executable = 0
    writable_executable = 0
    for section in sections:
        characteristics = int(section.characteristics or "0", 16)
        is_executable = bool(characteristics & 0x20000000)
        is_writable = bool(characteristics & 0x80000000)
        executable += int(is_executable)
        writable_executable += int(is_executable and is_writable)
    return PEStaticFeatures(
        tls_callbacks_present=False,
        overlay_present=False,
        overlay_size=0,
        import_descriptor_count=0,
        executable_section_count=executable,
        writable_executable_section_count=writable_executable,
        entry_point_section=None,
        suspicious_entry_point_section=False,
    )


def _hash_slice(path: Path, offset: int, size: int) -> HashSet:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1(usedforsecurity=False)
    md5 = hashlib.md5(usedforsecurity=False)
    remaining = size
    with path.open("rb") as file:
        file.seek(offset)
        while remaining > 0:
            chunk = file.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            remaining -= len(chunk)
    return HashSet(sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), md5=md5.hexdigest())


def _overlay_offset(data: bytes, sections: list[PESectionRange]) -> int:
    if not sections:
        return len(data)
    return min(len(data), max(section.raw_offset + section.raw_size for section in sections))


def _rva_to_offset(rva: int, sections: list[PESectionRange]) -> int | None:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            return section.raw_offset + (rva - section.virtual_address)
    return None


def _section_name_for_rva(rva: int, sections: list[PESectionRange]) -> str | None:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            return section.name
    return None


def _is_suspicious_entry_section(section_name: str | None) -> bool:
    if section_name is None:
        return False
    lowered = section_name.lower()
    return lowered not in {".text", "text", "code", ".code"} or "pack" in lowered


def _read_c_string(data: bytes, offset: int | None) -> str:
    if offset is None or offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _u16(data: bytes, offset: int) -> int:
    return int(unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(unpack_from("<I", data, offset)[0])
