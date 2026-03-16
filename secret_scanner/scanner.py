from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable, List, Sequence
from urllib.parse import urlparse

from .analysis import AhoCorasickAutomaton, cached_context_window, mixity_score, seems_false_positive, shannon_entropy
from .dedupe import MinHashLSH
from .extract import ContentExtractor
from .fetch import AsyncFetcher, DEBUG_ENDPOINTS
from .ml_filter import ContextModel
from .patterns import EXTENSION_CATEGORY_FILTER, KEYWORDS, PATTERNS, PatternDef


@dataclass
class Finding:
    category: str
    rule_name: str
    severity: str
    extracted_value: str
    entropy_score: float
    mixity_score: float
    source_location: str
    snippet: str
    verification_status: str


class SecretScanner:
    def __init__(self) -> None:
        self.prefilter = AhoCorasickAutomaton(KEYWORDS)
        self.extractor = ContentExtractor()
        self.fetcher = AsyncFetcher()
        self.context_ml = ContextModel()
        self.context_ml.fit_or_load()
        self.dedupe = MinHashLSH()

    def _patterns_for_source(self, source: str) -> list[PatternDef]:
        ext = Path(urlparse(source).path).suffix.lower()
        cats = EXTENSION_CATEGORY_FILTER.get(ext)
        if not cats:
            return PATTERNS
        return [p for p in PATTERNS if p.category in cats]

    def _truncate(self, v: str, n: int = 32) -> str:
        return v if len(v) <= n else f"{v[:n]}..."

    def _verification_status(self, score: float, entropy: float) -> str:
        if score >= 0.75 and entropy >= 3.0:
            return "likely_valid"
        if score >= 0.45:
            return "needs_review"
        return "likely_false_positive"

    def scan_text(self, source: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if not self.prefilter.contains_any(text):
            return findings

        for pattern in self._patterns_for_source(source):
            for m in pattern.regex.finditer(text):
                value = m.group(0)
                entropy = shannon_entropy(value)
                mix = mixity_score(value)
                if entropy < pattern.min_entropy or mix < pattern.min_mixity:
                    continue
                ctx = cached_context_window(text, m.start(), m.end())
                var_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*$", text[max(0, m.start() - 40):m.start()])
                var_name = var_match.group(1) if var_match else None
                if seems_false_positive(value, ctx, var_name):
                    continue
                ml_score = self.context_ml.score(ctx)
                status = self._verification_status(ml_score, entropy)
                dedupe_key = f"{pattern.name}:{source}:{m.start()}"
                if self.dedupe.is_duplicate(dedupe_key, value):
                    continue
                findings.append(
                    Finding(
                        category=pattern.category,
                        rule_name=pattern.name,
                        severity=pattern.severity,
                        extracted_value=self._truncate(value),
                        entropy_score=entropy,
                        mixity_score=mix,
                        source_location=source,
                        snippet=self._truncate(ctx, 180),
                        verification_status=status,
                    )
                )
        return findings

    async def scan_urls(self, urls: Sequence[str]) -> list[Finding]:
        alive = await self.fetcher.resolve_hosts(urls)
        tasks = []
        expanded = set(alive)
        for u in alive:
            for p in DEBUG_ENDPOINTS:
                expanded.add(u.rstrip("/") + p)
        for url in expanded:
            tasks.append(self.fetcher.fetch(url))

        responses = [r for r in await asyncio.gather(*tasks) if r is not None and r.status_code != 304]
        baseline = [len(r.text) for r in responses[:5]]
        findings: list[Finding] = []
        for resp in responses:
            if self.extractor.soft_404(baseline, resp.headers.get("content-type", ""), resp.text, resp.url):
                continue
            for chunk in self.extractor.extract(resp.url, resp.text):
                findings.extend(self.scan_text(chunk.source, chunk.content))
        return findings

    async def aclose(self) -> None:
        await self.fetcher.aclose()
