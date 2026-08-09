"""Filesystem-backed hostile sample storage."""

import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StoredBinary:
    """Internal storage reference for a sample binary."""

    storage_ref: str
    path: Path


class LocalSampleStorage:
    """Store uploaded binaries as inert data under controlled paths."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def store_temp_file(self, temp_path: Path) -> StoredBinary:
        storage_ref = f"{uuid.uuid4().hex}.sample"
        final_path = self.root / storage_ref
        shutil.move(str(temp_path), final_path)
        _remove_execute_bits(final_path)
        return StoredBinary(storage_ref=storage_ref, path=final_path)

    def resolve(self, storage_ref: str) -> Path:
        candidate = (self.root / storage_ref).resolve()
        root = self.root.resolve()
        if not candidate.is_file() or root not in candidate.parents:
            msg = "stored sample not found"
            raise FileNotFoundError(msg)
        return candidate


def _remove_execute_bits(path: Path) -> None:
    if os.name == "nt":
        return
    mode = path.stat().st_mode
    path.chmod(mode & ~0o111)
