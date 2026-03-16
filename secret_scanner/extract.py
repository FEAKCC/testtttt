from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")
CSS_COMMENT = re.compile(r"/\*([\s\S]*?)\*/")
INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>", re.IGNORECASE)
HTML_LIKE = re.compile(r"<\s*html|<\s*body|<\s*!doctype", re.IGNORECASE)


@dataclass
class ExtractedText:
    source: str
    content: str


class ContentExtractor:
    def soft_404(self, baseline_sizes: list[int], content_type: str, body: str, url: str) -> bool:
        if baseline_sizes:
            mean = sum(baseline_sizes) / len(baseline_sizes)
            if abs(len(body) - mean) / max(1, mean) < 0.08:
                return True
        lower_ct = (content_type or "").lower()
        ext = Path(url).suffix.lower()
        if ext in {".js", ".json", ".css", ".xml", ".map"} and "text/html" in lower_ct and HTML_LIKE.search(body):
            return True
        return False

    def extract(self, url: str, body: str) -> List[ExtractedText]:
        chunks: List[ExtractedText] = [ExtractedText(url, body)]
        chunks.extend(ExtractedText(f"{url}#html_comment", c) for c in HTML_COMMENT.findall(body))
        chunks.extend(ExtractedText(f"{url}#css_comment", c) for c in CSS_COMMENT.findall(body))
        chunks.extend(ExtractedText(f"{url}#inline_script", c) for c in INLINE_SCRIPT.findall(body))

        if url.endswith(".map"):
            try:
                parsed = json.loads(body)
                for idx, src in enumerate(parsed.get("sourcesContent", []) or []):
                    if src:
                        chunks.append(ExtractedText(f"{url}#sourcemap[{idx}]", src))
            except json.JSONDecodeError:
                pass
        return chunks

    def expand_debug_endpoints(self, url: str) -> list[str]:
        base = url.rstrip("/")
        return [base + p for p in ["/actuator", "/actuator/env", "/graphql", "/rails/info/routes"]]
