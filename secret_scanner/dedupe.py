from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Dict, Iterable, List, Tuple


@dataclass
class LSHKey:
    band: int
    sig: str


class MinHashLSH:
    def __init__(self, permutations: int = 64, bands: int = 8) -> None:
        self.permutations = permutations
        self.bands = bands
        self.rows = permutations // bands
        self.buckets: Dict[Tuple[int, str], list[str]] = {}
        self.signatures: Dict[str, tuple[int, ...]] = {}

    def _shingles(self, text: str, k: int = 3) -> set[str]:
        if len(text) <= k:
            return {text}
        return {text[i : i + k] for i in range(len(text) - k + 1)}

    def _sig(self, text: str) -> tuple[int, ...]:
        shingles = self._shingles(text)
        sig = []
        for i in range(self.permutations):
            minimum = min(int(hashlib.sha1(f"{i}:{s}".encode()).hexdigest(), 16) for s in shingles)
            sig.append(minimum)
        return tuple(sig)

    def _sim(self, a: tuple[int, ...], b: tuple[int, ...]) -> float:
        same = sum(1 for x, y in zip(a, b) if x == y)
        return same / len(a)

    def is_duplicate(self, key: str, value: str, threshold: float = 0.82) -> bool:
        sig = self._sig(value)
        self.signatures[key] = sig
        for band in range(self.bands):
            start = band * self.rows
            end = start + self.rows
            band_sig = hashlib.md5(str(sig[start:end]).encode()).hexdigest()
            bucket_key = (band, band_sig)
            for existing in self.buckets.get(bucket_key, []):
                if self._sim(sig, self.signatures[existing]) >= threshold:
                    return True
            self.buckets.setdefault(bucket_key, []).append(key)
        return False
