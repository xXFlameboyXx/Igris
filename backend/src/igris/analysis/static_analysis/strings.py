"""Static string extraction."""

from collections.abc import Iterable

from igris.analysis.static_analysis.taxonomy import classify_string
from igris.schemas.file_intelligence import SectionMetadata
from igris.schemas.static_analysis import ExtractedString

PRINTABLE_ASCII = set(range(32, 127)) | {9}


def extract_strings(
    data: bytes,
    *,
    min_length: int,
    max_strings: int,
    sections: Iterable[SectionMetadata],
) -> list[ExtractedString]:
    section_ranges = _section_ranges(sections)
    strings = _extract_ascii(data, min_length, section_ranges, max_strings)
    remaining = max_strings - len(strings)
    if remaining > 0:
        strings.extend(_extract_utf16le(data, min_length, section_ranges, remaining))
    return strings[:max_strings]


def _extract_ascii(
    data: bytes,
    min_length: int,
    section_ranges: list[tuple[int, int, str]],
    max_strings: int,
) -> list[ExtractedString]:
    extracted: list[ExtractedString] = []
    start: int | None = None
    buffer = bytearray()

    for offset, byte in enumerate(data):
        if byte in PRINTABLE_ASCII:
            if start is None:
                start = offset
            buffer.append(byte)
            continue
        if start is not None and len(buffer) >= min_length:
            value = buffer.decode("ascii", errors="replace")
            extracted.append(
                ExtractedString(
                    value=value,
                    offset=start,
                    encoding="ascii",
                    category=classify_string(value),
                    section=_section_for_offset(start, section_ranges),
                )
            )
            if len(extracted) >= max_strings:
                return extracted
        start = None
        buffer.clear()

    if start is not None and len(buffer) >= min_length and len(extracted) < max_strings:
        value = buffer.decode("ascii", errors="replace")
        extracted.append(
            ExtractedString(
                value=value,
                offset=start,
                encoding="ascii",
                category=classify_string(value),
                section=_section_for_offset(start, section_ranges),
            )
        )
    return extracted


def _extract_utf16le(
    data: bytes,
    min_length: int,
    section_ranges: list[tuple[int, int, str]],
    max_strings: int,
) -> list[ExtractedString]:
    extracted: list[ExtractedString] = []
    start: int | None = None
    chars = bytearray()
    index = 0

    while index + 1 < len(data):
        byte = data[index]
        null = data[index + 1]
        if byte in PRINTABLE_ASCII and null == 0:
            if start is None:
                start = index
            chars.append(byte)
            index += 2
            continue
        if start is not None and len(chars) >= min_length:
            value = chars.decode("ascii", errors="replace")
            extracted.append(
                ExtractedString(
                    value=value,
                    offset=start,
                    encoding="utf-16le",
                    category=classify_string(value),
                    section=_section_for_offset(start, section_ranges),
                )
            )
            if len(extracted) >= max_strings:
                return extracted
        start = None
        chars.clear()
        index += 2

    if start is not None and len(chars) >= min_length and len(extracted) < max_strings:
        value = chars.decode("ascii", errors="replace")
        extracted.append(
            ExtractedString(
                value=value,
                offset=start,
                encoding="utf-16le",
                category=classify_string(value),
                section=_section_for_offset(start, section_ranges),
            )
        )
    return extracted


def _section_ranges(sections: Iterable[SectionMetadata]) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for section in sections:
        if section.raw_offset is None or section.raw_size <= 0:
            continue
        ranges.append((section.raw_offset, section.raw_offset + section.raw_size, section.name))
    return ranges


def _section_for_offset(offset: int, ranges: list[tuple[int, int, str]]) -> str | None:
    for start, end, name in ranges:
        if start <= offset < end:
            return name
    return None
