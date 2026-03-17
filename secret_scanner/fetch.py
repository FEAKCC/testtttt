from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
import random
import socket
from typing import Dict, Iterable, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None


DEBUG_ENDPOINTS = [
    "/actuator",
    "/actuator/env",
    "/actuator/configprops",
    "/graphql",
    "/graphql?query={__schema{types{name}}}",
    "/rails/info/routes",
    "/rails/info/properties",
]


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: dict
    text: str
    elapsed_ms: int


class CircuitState:
    def __init__(self, threshold: int = 4, cooldown_s: int = 90) -> None:
        self.failures = 0
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self.open_until: Optional[datetime] = None

    def can_request(self) -> bool:
        return not self.open_until or datetime.utcnow() >= self.open_until

    def on_success(self) -> None:
        self.failures = 0
        self.open_until = None

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.open_until = datetime.utcnow() + timedelta(seconds=self.cooldown_s)


class AsyncFetcher:
    def __init__(self, concurrency_per_domain: int = 6, timeout_s: int = 15) -> None:
        self.timeout_s = timeout_s
        self.client = None
        if httpx is not None:
            timeout = httpx.Timeout(timeout_s)
            limits = httpx.Limits(max_connections=200, max_keepalive_connections=50, keepalive_expiry=35)
            self.client = httpx.AsyncClient(http2=True, timeout=timeout, limits=limits, follow_redirects=True, headers={
                "User-Agent": "ReconSecretScanner/0.1",
                "Accept-Encoding": "gzip, br",
            })
        self.domain_sem: Dict[str, asyncio.Semaphore] = {}
        self.circuit: Dict[str, CircuitState] = {}
        self.etags: Dict[str, str] = {}
        self.last_modified: Dict[str, str] = {}
        self.concurrency_per_domain = concurrency_per_domain

    async def aclose(self) -> None:
        if self.client is not None:
            await self.client.aclose()

    @staticmethod
    def _host_looks_valid(host: str) -> bool:
        host = host.strip().strip(".")
        if not host:
            return False
        # Avoid empty labels such as "..example.com" or "."
        return all(label for label in host.split("."))

    async def resolve_hosts(self, urls: Iterable[str]) -> list[str]:
        out = []
        loop = asyncio.get_running_loop()
        for url in urls:
            try:
                host = (urlparse(url).hostname or "").strip()
            except ValueError:
                continue
            if not host or not self._host_looks_valid(host):
                continue
            try:
                await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                out.append(url)
            except (socket.gaierror, UnicodeError, ValueError, OSError):
                continue
        return out

    async def _fallback_get(self, url: str, headers: dict) -> FetchResult:
        def _run() -> FetchResult:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                return FetchResult(url, resp.status, dict(resp.headers.items()), body, 0)

        return await asyncio.to_thread(_run)

    async def fetch(self, url: str, retries: int = 3) -> Optional[FetchResult]:
        host = urlparse(url).hostname or ""
        sem = self.domain_sem.setdefault(host, asyncio.Semaphore(self.concurrency_per_domain))
        circuit = self.circuit.setdefault(host, CircuitState())
        if not circuit.can_request():
            return None

        headers = {"Accept-Encoding": "gzip, br", "User-Agent": "ReconSecretScanner/0.1"}
        if url in self.etags:
            headers["If-None-Match"] = self.etags[url]
        if url in self.last_modified:
            headers["If-Modified-Since"] = self.last_modified[url]

        async with sem:
            for i in range(retries + 1):
                try:
                    if self.client is not None:
                        resp = await self.client.get(url, headers=headers)
                        result = FetchResult(url, resp.status_code, dict(resp.headers), resp.text, int(resp.elapsed.total_seconds() * 1000))
                    else:
                        result = await self._fallback_get(url, headers)
                    if etag := result.headers.get("etag"):
                        self.etags[url] = etag
                    if lm := result.headers.get("last-modified"):
                        self.last_modified[url] = lm
                    if result.status_code >= 500:
                        raise RuntimeError("server error")
                    circuit.on_success()
                    return result
                except Exception:
                    circuit.on_failure()
                    if i == retries:
                        return None
                    await asyncio.sleep((2**i) + random.uniform(0.05, 0.45))
        return None
