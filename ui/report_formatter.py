"""
Rich terminal formatter for CVE agent audit logs.
Usage:
    uv run python -m ui.report_formatter agent/audit7_tidy.log
"""

import re
import sys
from dataclasses import dataclass, field

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()


@dataclass
class Finding:
    tier: str
    title: str
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    file_lines: list[str] = field(default_factory=list)
    description: str = ""


def _table_rows(content: str) -> list[list[str]]:
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"^\|[\s:|-]+\|", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and cells[0].lower().strip("* ") in ("id", "cve id", "vulnerability"):
            continue
        rows.append(cells)
    return rows


def _parse_findings(content: str, tier: str) -> list[Finding]:
    findings = []
    for cells in _table_rows(content):
        if len(cells) < 3:
            continue

        id_cell = cells[0]
        pkg_cell = cells[1] if len(cells) > 1 else ""
        file_cell = cells[2] if len(cells) > 2 else ""
        snippet_cell = cells[3] if len(cells) > 3 else ""
        fix_cell = cells[4] if len(cells) > 4 else ""

        cve_ids = re.findall(r"CVE-[\d-]+", id_cell)
        cwe_ids = re.findall(r"CWE-\d+", id_cell)
        file_lines = re.findall(r"`([^`]+)`", file_cell)

        pkg = re.sub(r"`", "", pkg_cell).split("/")[-1].strip()
        ids_label = (
            " / ".join(cve_ids + cwe_ids) or re.sub(r"\*\*|`", "", id_cell).strip()
        )
        title = (
            f"{ids_label}  ({pkg})" if pkg and pkg.lower() != "custom" else ids_label
        )

        description = re.sub(r"`", "", snippet_cell).strip()
        if fix_cell:
            description += "  →  " + re.sub(r"`", "", fix_cell).strip()

        findings.append(
            Finding(
                tier=tier,
                title=title,
                cve_ids=list(dict.fromkeys(cve_ids)),
                cwe_ids=list(dict.fromkeys(cwe_ids)),
                file_lines=file_lines[:4],
                description=description,
            )
        )
    return findings


def _parse_unreached(content: str) -> list[Finding]:
    findings = []
    for cells in _table_rows(content):
        if len(cells) < 2:
            continue
        cve_ids = re.findall(r"CVE-[\d-]+", cells[0])
        title = re.sub(r"\*\*", "", cells[0]).strip()
        desc = cells[3] if len(cells) > 3 else (cells[1] if len(cells) > 1 else "")
        findings.append(
            Finding(tier="UNREACHED", title=title, cve_ids=cve_ids, description=desc)
        )
    return findings


def parse_report(report: str) -> dict[str, list[Finding]]:
    result: dict[str, list[Finding]] = {"CONFIRMED": [], "LIKELY": [], "UNREACHED": []}

    parts = re.split(r"##\s+(CONFIRMED|LIKELY|UNREACHED)\b", report)
    i = 1
    while i + 1 < len(parts):
        tier = parts[i].strip()
        content = parts[i + 1]
        i += 2
        if tier == "UNREACHED":
            result[tier] = _parse_unreached(content)
        elif tier in result:
            result[tier] = _parse_findings(content, tier)

    return result


def _findings_table(findings: list[Finding], color: str) -> Table:
    t = Table(
        box=box.SIMPLE_HEAVY,
        show_lines=True,
        header_style=f"bold {color}",
        border_style=color,
    )
    t.add_column("#", style="dim", width=3, no_wrap=True)
    t.add_column("Vulnerability", min_width=28, max_width=40)
    t.add_column("CVE / CWE", min_width=18, max_width=22)
    t.add_column("File : Line", min_width=28, max_width=38, style="cyan")
    t.add_column("Description", min_width=36, overflow="fold")

    for i, f in enumerate(findings, 1):
        ids = "\n".join(f.cve_ids + f.cwe_ids) or "—"
        files = "\n".join(f.file_lines) or "—"
        desc = f.description[:220] + "…" if len(f.description) > 220 else f.description
        t.add_row(str(i), Text(f.title, style="bold"), ids, files, desc)

    return t


def _unreached_table(findings: list[Finding]) -> Table:
    t = Table(box=box.SIMPLE, show_lines=False, header_style="dim", border_style="dim")
    t.add_column("CVE", min_width=20, max_width=24, style="dim")
    t.add_column("Package", min_width=14, max_width=18, style="dim")
    t.add_column("Summary", min_width=50, overflow="fold", style="dim")

    for f in findings:
        cve = "\n".join(f.cve_ids) if f.cve_ids else f.title
        pkg = re.sub(r"CVE-[\d-]+", "", f.title).strip(" /()") or "—"
        t.add_row(cve, pkg, f.description[:120])

    return t


def format_report(report: str, owner_repo: str = "") -> None:
    findings = parse_report(report)
    confirmed = findings["CONFIRMED"]
    likely = findings["LIKELY"]
    unreached = findings["UNREACHED"]

    console.print()

    header = Text("  🔍 CVE Security Audit", style="bold white")
    if owner_repo:
        header.append(f"   ·   {owner_repo}", style="bold bright_blue")
    console.print(Panel(header, style="blue", padding=(0, 1)))

    summary = Table(box=box.ROUNDED, show_header=False, padding=(0, 4), expand=False)
    summary.add_column(justify="center", min_width=18)
    summary.add_column(justify="center", min_width=18)
    summary.add_column(justify="center", min_width=18)
    summary.add_row(
        Text(f"🔴  CONFIRMED\n    {len(confirmed)}", style="bold red"),
        Text(f"🟡  LIKELY\n    {len(likely)}", style="bold yellow"),
        Text(f"⚪  UNREACHED\n    {len(unreached)}", style="dim white"),
    )
    console.print(summary)
    console.print()

    if confirmed:
        console.print(Rule("[bold red]🔴  CONFIRMED Vulnerabilities[/]", style="red"))
        console.print(_findings_table(confirmed, "red"))

    if likely:
        console.print(
            Rule("[bold yellow]🟡  LIKELY Vulnerabilities[/]", style="yellow")
        )
        console.print(_findings_table(likely, "yellow"))

    if unreached:
        console.print(
            Rule(
                "[dim]⚪  UNREACHED  (in deps, no reachable call site)[/]", style="dim"
            )
        )
        console.print(_unreached_table(unreached))

    console.print()


def _extract_report(raw: str) -> tuple[str, str]:
    # Audit log format: Python dict literal with 'text': '...' key
    m = re.search(r"'text':\s*'(.*?)'\s*,\s*'extras'", raw, re.DOTALL)
    if m:
        text = m.group(1).replace("\\n", "\n").replace("\\t", "\t")
        return "", text
    # Fallback: find markdown anchor
    for anchor in ("# Security Audit Report", "## CONFIRMED"):
        idx = raw.find(anchor)
        if idx != -1:
            return "", raw[idx:]
    return "", raw


def main():
    raw = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    owner_repo, report_text = _extract_report(raw)
    format_report(report_text, owner_repo)
