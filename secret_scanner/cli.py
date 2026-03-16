from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import re

from .reporting import write_html, write_json, write_sarif
from .scanner import SecretScanner

SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="High-performance async secret discovery scanner")
    p.add_argument("--url", action="append", default=[], help="Target URL (repeatable)")
    p.add_argument("--url-file", help="File containing target URLs/domains/IPs (one per line)")
    p.add_argument("--text-file", action="append", default=[], help="Local text file to scan")
    p.add_argument(
        "--schemes",
        default="https,http",
        help="Comma-separated schemes added to bare domains/IPs from --url/--url-file (default: https,http)",
    )
    p.add_argument("--out-json", default="findings.json")
    p.add_argument("--out-sarif", default="findings.sarif")
    p.add_argument("--out-html", default="findings.html")
    return p.parse_args()


def _read_url_lines(path: str) -> list[str]:
    lines = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        lines.append(candidate)
    return lines


def _expand_target(target: str, schemes: list[str]) -> list[str]:
    if SCHEME_RE.match(target):
        return [target]
    if target.startswith("//"):
        target = target[2:]
    if "/" in target:
        return [f"{scheme}://{target}" for scheme in schemes]
    return [f"{scheme}://{target}" for scheme in schemes]


def load_urls(args: argparse.Namespace) -> list[str]:
    schemes = [s.strip().lower() for s in args.schemes.split(",") if s.strip()]
    raw_targets = list(args.url)
    if args.url_file:
        raw_targets.extend(_read_url_lines(args.url_file))

    expanded = []
    for target in raw_targets:
        expanded.extend(_expand_target(target.strip(), schemes))

    # preserve order while deduplicating
    return list(dict.fromkeys(expanded))


async def run_async(args: argparse.Namespace) -> int:
    scanner = SecretScanner()
    findings = []

    try:
        urls = load_urls(args)
        if urls:
            findings.extend(await scanner.scan_urls(urls))

        for fpath in args.text_file:
            p = Path(fpath)
            if p.exists():
                findings.extend(scanner.scan_text(str(p), p.read_text(encoding="utf-8", errors="ignore")))

        write_json(findings, args.out_json)
        write_sarif(findings, args.out_sarif)
        write_html(findings, args.out_html)
        print(
            json.dumps(
                {
                    "targets": len(urls),
                    "findings": len(findings),
                    "json": args.out_json,
                    "sarif": args.out_sarif,
                    "html": args.out_html,
                }
            )
        )
        return 0
    finally:
        await scanner.aclose()


def main() -> None:
    args = parse_args()
    raise SystemExit(asyncio.run(run_async(args)))


if __name__ == "__main__":
    main()
