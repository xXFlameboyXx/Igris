"""Shannon entropy helpers."""

from collections.abc import Iterable
from math import log2
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


class EntropyCalculator:
    """Incremental Shannon entropy calculator for byte streams."""

    def __init__(self) -> None:
        self._counts = [0] * 256
        self._total = 0

    def update(self, data: bytes) -> None:
        for byte in data:
            self._counts[byte] += 1
        self._total += len(data)

    def digest(self) -> float:
        if self._total == 0:
            return 0.0
        entropy = 0.0
        for count in self._counts:
            if count:
                probability = count / self._total
                entropy -= probability * log2(probability)
        return round(entropy, 6)


def shannon_entropy(chunks: Iterable[bytes]) -> float:
    calculator = EntropyCalculator()
    for chunk in chunks:
        calculator.update(chunk)
    return calculator.digest()


def file_entropy(path: Path) -> float:
    calculator = EntropyCalculator()
    with path.open("rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            calculator.update(chunk)
    return calculator.digest()


def slice_entropy(path: Path, offset: int, size: int) -> float:
    if size <= 0:
        return 0.0

    calculator = EntropyCalculator()
    remaining = size
    with path.open("rb") as file:
        file.seek(offset)
        while remaining > 0:
            chunk = file.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                break
            calculator.update(chunk)
            remaining -= len(chunk)
    return calculator.digest()
