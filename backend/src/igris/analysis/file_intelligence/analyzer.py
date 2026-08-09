"""Phase 1 file intelligence analyzer."""

from pathlib import Path

from igris.analysis.file_intelligence.elf import ELFParseError, parse_elf
from igris.analysis.file_intelligence.entropy import file_entropy
from igris.analysis.file_intelligence.identification import detect_format, detect_mime_type
from igris.analysis.file_intelligence.pe import PEParseError, parse_pe
from igris.schemas.file_intelligence import (
    DetectedFormat,
    FileMetadata,
    MetadataValue,
)


def analyze_file(path: Path) -> FileMetadata:
    """Analyze a file as hostile data and return normalized metadata."""

    detected_format = detect_format(path)
    mime_type = detect_mime_type(detected_format)
    size_bytes = path.stat().st_size
    entropy = file_entropy(path)
    parse_errors: list[str] = []
    architecture: str | None = None
    entry_point = MetadataValue.not_applicable()
    pe = None
    elf = None

    if detected_format == DetectedFormat.PE:
        try:
            pe = parse_pe(path)
            architecture = pe.architecture
            entry_point = pe.entry_point
        except PEParseError as exc:
            parse_errors.append(f"PE parse failed: {exc}")
            entry_point = MetadataValue.failed(str(exc))
    elif detected_format == DetectedFormat.ELF:
        try:
            elf = parse_elf(path)
            architecture = elf.architecture
            entry_point = elf.entry_point
        except ELFParseError as exc:
            parse_errors.append(f"ELF parse failed: {exc}")
            entry_point = MetadataValue.failed(str(exc))

    return FileMetadata(
        size_bytes=size_bytes,
        detected_format=detected_format,
        architecture=architecture,
        mime_type=mime_type,
        entropy=entropy,
        created_at=MetadataValue.not_present(),
        modified_at=MetadataValue.not_present(),
        entry_point=entry_point,
        pe=pe,
        elf=elf,
        parse_errors=parse_errors,
    )
