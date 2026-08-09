"""Content-based file identification."""

from pathlib import Path

from igris.schemas.file_intelligence import DetectedFormat


def detect_format(path: Path) -> DetectedFormat:
    with path.open("rb") as file:
        header = file.read(512)

    if len(header) == 0:
        return DetectedFormat.EMPTY
    if header.startswith(b"MZ"):
        return DetectedFormat.PE
    if header.startswith(b"\x7fELF"):
        return DetectedFormat.ELF
    if _looks_like_text(header):
        return DetectedFormat.TEXT
    return DetectedFormat.UNKNOWN


def detect_mime_type(detected_format: DetectedFormat) -> str:
    return {
        DetectedFormat.EMPTY: "application/x-empty",
        DetectedFormat.PE: "application/vnd.microsoft.portable-executable",
        DetectedFormat.ELF: "application/x-elf",
        DetectedFormat.TEXT: "text/plain",
        DetectedFormat.UNKNOWN: "application/octet-stream",
    }[detected_format]


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    allowed_controls = {9, 10, 13}
    printable = sum(1 for byte in data if 32 <= byte <= 126 or byte in allowed_controls)
    return printable / len(data) > 0.95
