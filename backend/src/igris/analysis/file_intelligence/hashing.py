"""Incremental hashing helpers."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from igris.analysis.file_intelligence.entropy import CHUNK_SIZE, EntropyCalculator
from igris.schemas.file_intelligence import HashSet


@dataclass(frozen=True)
class FileDigest:
    """Hashes, size, and entropy calculated while streaming a file."""

    hashes: HashSet
    size_bytes: int
    entropy: float


def digest_file(path: Path) -> FileDigest:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1(usedforsecurity=False)
    md5 = hashlib.md5(usedforsecurity=False)
    entropy = EntropyCalculator()
    size_bytes = 0

    with path.open("rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            entropy.update(chunk)
            size_bytes += len(chunk)

    return FileDigest(
        hashes=HashSet(sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), md5=md5.hexdigest()),
        size_bytes=size_bytes,
        entropy=entropy.digest(),
    )
