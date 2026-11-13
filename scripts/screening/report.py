"""Write the Markdown report.

Almost every string in the report comes from the package being screened (names,
file paths, event details). Those strings are untrusted, so md() neutralizes the
characters that could break a table cell, a code span, or the layout.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Report


def md(text) -> str:
    """Make untrusted text safe inside a table cell, list item, or code span."""
    s = str(text).replace("\r", " ").replace("\n", " ")
    s = s.replace("|", "\\|").replace("`", "'")
    return s


def _coverage_row(report: Report, eco: str) -> str:
    cov = report.coverage.get(eco, {})
    if eco == "pypi":
        default_install = "skipped: no setup.py or pyproject.toml to install"
    else:
        default_install = "not supported yet (static only)"
    manifests = ", ".join(f"`{md(m)}`" for m in report.ecosystems[eco][:4])
    return (f"| {eco} | {manifests} "
            f"| {md(cov.get('known vulnerabilities', 'n/a'))} "
            f"| {md(cov.get('heuristics', 'n/a'))} "
            f"| {md(cov.get('install in sandbox', default_install))} |")


def render(report: Report, stamp: str) -> str:
    lines = [
        "# Dependency screening report",
        "",
        f"- Target: `{md(report.target)}`",
        f"- Generated: {stamp}",
        f"- **Verdict: {report.verdict.upper()}**",
    ]
    if report.install_exit is not None:
        lines.append(f"- Install exit code: {report.install_exit}")

    lines += ["", "## Coverage", "",
              "| Ecosystem | Manifests found | Known vulnerabilities | Heuristics | Install in sandbox |",
              "|---|---|---|---|---|"]
    lines += [_coverage_row(report, eco) for eco in sorted(report.ecosystems)]
    if not report.ecosystems:
        lines.append("| - | none | - | - | - |")

    lines += ["", "## Findings"]
    if report.findings:
        lines += [f"- **{f.severity.upper()}** ({f.stage}) {md(f.message)}"
                  for f in report.findings]
    else:
        lines.append("- None")

    lines += ["", "## Runtime events", ""]
    lines += ([f"- `{md(json.dumps(e))}`" for e in report.events] or ["- None"])

    lines += ["", "## Tool notes", ""]
    # Tool output can be long and contain anything, so it goes in a fenced block.
    # A fence longer than any backtick run inside the text keeps the block closed.
    for note in report.tool_notes:
        fence = "`" * max(3, _longest_backtick_run(note) + 1)
        lines.append(f"{fence}\n{note}\n{fence}")
    if not report.tool_notes:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def _longest_backtick_run(text: str) -> int:
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return longest


def write_report(report: Report, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out.write_text(render(report, stamp))
