from __future__ import annotations

from collections import Counter, deque
import math
import re
from functools import lru_cache
from typing import Dict, Iterable, List

PLACEHOLDER_WORDS = {
    "example",
    "changeme",
    "your_token_here",
    "dummy",
    "sample",
    "test",
    "placeholder",
    "xxxx",
    "abc123",
    "lorem",
    "token_here",
    "set_me",
}

DOC_HINTS = {"readme", "documentation", "docs", "example", "tutorial", "how to", "sample"}
HEXISH = re.compile(r"^[a-f0-9]{32,}$")
VERSION = re.compile(r"^v?\d+\.\d+(\.\d+)?$")
REPEATED = re.compile(r"(.)\1{7,}")
ENV_REF = re.compile(r"\$\{?[A-Z0-9_]+\}?")
CDN_URL_CRED = re.compile(r"https?://(?:cdn|static|assets)\.[^\s]+")


class AhoCorasickAutomaton:
    def __init__(self, keywords: Iterable[str]) -> None:
        self.goto: List[Dict[str, int]] = [{}]
        self.fail = [0]
        self.output: List[set[str]] = [set()]
        for w in keywords:
            self._insert(w)
        self._build_failures()

    def _insert(self, word: str) -> None:
        state = 0
        for ch in word:
            state = self.goto[state].setdefault(ch, len(self.goto))
            if state == len(self.fail):
                self.goto.append({})
                self.fail.append(0)
                self.output.append(set())
        self.output[state].add(word)

    def _build_failures(self) -> None:
        q = deque(self.goto[0].values())
        while q:
            r = q.popleft()
            for ch, s in self.goto[r].items():
                q.append(s)
                state = self.fail[r]
                while state and ch not in self.goto[state]:
                    state = self.fail[state]
                self.fail[s] = self.goto[state].get(ch, 0)
                self.output[s].update(self.output[self.fail[s]])

    def contains_any(self, text: str) -> bool:
        state = 0
        for ch in text.lower():
            while state and ch not in self.goto[state]:
                state = self.fail[state]
            state = self.goto[state].get(ch, 0)
            if self.output[state]:
                return True
        return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def mixity_score(value: str) -> float:
    if not value:
        return 0.0
    pools = [any(c.islower() for c in value), any(c.isupper() for c in value), any(c.isdigit() for c in value), any(not c.isalnum() for c in value)]
    return sum(pools) / 4.0


def seems_false_positive(raw: str, context: str, variable_name: str | None = None) -> bool:
    low = raw.lower().strip()
    if low in PLACEHOLDER_WORDS or any(w in low for w in PLACEHOLDER_WORDS):
        return True
    if ENV_REF.search(raw):
        return True
    if HEXISH.match(low) or VERSION.match(low) or REPEATED.search(low):
        return True
    if CDN_URL_CRED.search(raw):
        return True
    c_low = context.lower()
    if any(h in c_low for h in DOC_HINTS):
        return True
    if variable_name and variable_name.strip().lower() == low:
        return True
    return False


@lru_cache(maxsize=2048)
def cached_context_window(text: str, start: int, end: int, pad: int = 80) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    return text[left:right]
