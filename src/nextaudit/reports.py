"""Human-readable and machine-readable reports, without matched secret values."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from .scanner import ScanReport

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def show_report(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()
    counts = report.to_dict()["summary"]
    console.print(f"[bold]Target:[/bold] {report.target}")
    console.print(f"Status: {report.status} | Framework: {report.framework} | Requests: {report.requests_made}")
    console.print(f"Pages: {len(report.pages)} | Scripts: {len(report.scripts)} | Maps: {len(report.source_maps)} | API paths: {len(report.api_endpoints)}")
    console.print("Findings: " + " · ".join(f"{s}={counts[s]}" for s in SEVERITY_ORDER))
    table = Table(title="Security review findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Location", overflow="fold")
    table.add_column("Evidence", overflow="fold")
    for finding in report.findings[:75]:
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}[finding.severity]
        table.add_row(f"[{color}]{finding.severity}[/{color}]", finding.rule_id, finding.location, finding.detail)
    console.print(table)
    if len(report.findings) > 75:
        console.print("Additional findings are in the saved report.")
    if report.errors:
        console.print(f"[yellow]Warnings: {len(report.errors)}; see report for details[/yellow]")
    console.print("[dim]Indicators only. Confirm exploitability manually; no scan can prove a site bug-free.[/dim]")


def sarif(report: ScanReport) -> dict[str, Any]:
    rules = {}
    results = []
    for f in report.findings:
        rules[f.rule_id] = {"id": f.rule_id, "shortDescription": {"text": f.title},
                            "help": {"text": f.remediation}}
        results.append({
            "ruleId": f.rule_id,
            "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}[f.severity],
            "message": {"text": f.detail + " | " + f.remediation},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location}}}],
            "properties": {"confidence": f.confidence, "severity": f.severity},
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "NextAudit", "version": report.scanner_version,
                                           "rules": sorted(rules.values(), key=lambda r: r["id"])}},
                      "results": results}]}


def markdown(report: ScanReport) -> str:
    lines = ["# NextAudit security review", "", f"- **Target:** `{report.target}`",
             f"- **Status:** `{report.status}`", f"- **Framework:** {report.framework}",
             f"- **Requests:** {report.requests_made}", f"- **Findings:** {len(report.findings)}", "",
             "## Findings", ""]
    for finding in report.findings:
        lines.extend([f"### {finding.severity}: {finding.title}", "",
                      f"- Rule: `{finding.rule_id}`", f"- Confidence: {finding.confidence}",
                      f"- Location: `{finding.location}`", f"- Evidence: {finding.detail}",
                      f"- Suggested fix: {finding.remediation}", ""])
    lines += ["## Coverage", "", f"Pages: {len(report.pages)}; scripts: {len(report.scripts)}; source maps: {len(report.source_maps)}.", "",
              "## Caveat", "", "Heuristic findings are not confirmed vulnerabilities. This read-only scanner does not test business logic, authorization bypasses, SQL injection, or exploitation.", ""]
    return "\n".join(lines)


def save_report(report: ScanReport, path: str, format_: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if format_ == "json":
        payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    elif format_ == "sarif":
        payload = json.dumps(sarif(report), ensure_ascii=False, indent=2)
    elif format_ == "markdown":
        payload = markdown(report)
    else:
        raise ValueError("Unknown report format")
    output.write_text(payload + "\n", encoding="utf-8")
