from __future__ import annotations

from dataclasses import asdict
import html
import json
from pathlib import Path
from typing import Iterable

from .scanner import Finding


def write_json(findings: Iterable[Finding], path: str) -> None:
    Path(path).write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")


def write_sarif(findings: Iterable[Finding], path: str) -> None:
    rules = {}
    results = []
    for f in findings:
        rid = f"{f.category}:{f.rule_name}"
        rules[rid] = {
            "id": rid,
            "name": f.rule_name,
            "shortDescription": {"text": f.category},
            "defaultConfiguration": {"level": "error" if f.severity in {"critical", "high"} else "warning"},
        }
        results.append(
            {
                "ruleId": rid,
                "message": {"text": f"{f.category} secret detected ({f.rule_name})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.source_location}}}],
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "recon-secretscanner", "rules": list(rules.values())}}, "results": results}],
    }
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def write_html(findings: Iterable[Finding], path: str) -> None:
    rows = "\n".join(
        f"<tr><td>{html.escape(f.category)}</td><td>{html.escape(f.rule_name)}</td><td>{f.severity}</td><td>{html.escape(f.extracted_value)}</td><td>{f.entropy_score:.2f}</td><td>{f.mixity_score:.2f}</td><td>{html.escape(f.source_location)}</td><td>{html.escape(f.verification_status)}</td></tr>"
        for f in findings
    )
    document = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Recon Secret Scanner Report</title>
<style>body{{font-family:Arial;margin:1rem;}} table{{border-collapse:collapse;width:100%;}}th,td{{border:1px solid #ccc;padding:6px;font-size:12px;}}</style>
</head><body><h1>Secret Discovery Findings</h1><table>
<thead><tr><th>Category</th><th>Rule</th><th>Severity</th><th>Value</th><th>Entropy</th><th>Mixity</th><th>Source</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
    Path(path).write_text(document, encoding="utf-8")
