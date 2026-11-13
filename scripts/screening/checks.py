"""Static checks: nothing is installed or executed, the files are only read.

  known vulnerabilities  OSV-Scanner, one recursive pass for all ecosystems
  heuristics             GuardDog, one run per detected ecosystem
  source patterns        regular expressions over Python source (install-time code)
"""
import json
import re
from pathlib import Path

from . import runner
from .detect import iter_files
from .models import Report
from .runner import ToolCall

# OSV-Scanner's ecosystem names -> this tool's ecosystem names.
OSV_NAMES = {"PyPI": "pypi", "npm": "npm", "Go": "go", "RubyGems": "rubygems"}

INSTALL_TIME_PATTERNS = {
    r"\bsocket\.": "raw socket use",
    r"\burllib|\brequests\.|\bhttpx\.|\bhttp\.client": "outbound HTTP client",
    r"\bsubprocess\.|\bos\.system\(|\bos\.popen\(": "process spawn",
    r"\bbase64\.b64decode|\bexec\(|\beval\(": "decode-and-execute pattern",
    r"~/\.(ssh|aws|netrc|env)|\.ssh/|\.aws/": "credential path reference",
}
MAX_SOURCE_BYTES = 2_000_000  # larger files are skipped and noted


def check_known_vulnerabilities(target: Path, mode: str, report: Report) -> None:
    call = ToolCall("osv-scanner",
                    ("scan", "source", "-r", "{target}", "--allow-no-lockfiles", "--format", "json"),
                    needs_network=True)
    proc = runner.run_tool(call, target, mode, report)
    if proc is None:
        for eco in report.ecosystems:
            report.cover(eco, "known vulnerabilities", "skipped (osv-scanner unavailable)")
        return
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        report.tool_notes.append(f"osv-scanner output not parseable (exit {proc.returncode})")
        for eco in report.ecosystems:
            report.cover(eco, "known vulnerabilities", "error")
        return

    checked = {eco: 0 for eco in report.ecosystems}
    for result in data.get("results", []):
        for entry in result.get("packages", []):
            pkg = entry.get("package", {})
            eco = OSV_NAMES.get(pkg.get("ecosystem", "").split(":")[0])
            if eco not in checked:  # not an ecosystem this run is about
                continue
            checked[eco] += 1
            vulns = entry.get("vulnerabilities", [])
            if vulns:
                ids = ", ".join(v.get("id", "?") for v in vulns[:3])
                report.add("warn", "static",
                           f"{pkg.get('name')} {pkg.get('version')} ({eco}): "
                           f"{len(vulns)} known vulnerabilities, e.g. {ids}")

    for eco, n in checked.items():
        report.cover(eco, "known vulnerabilities",
                     f"checked {n} package{'s' if n != 1 else ''}")


def check_heuristics(target: Path, mode: str, report: Report) -> None:
    for eco in sorted(report.ecosystems):
        call = ToolCall("guarddog", (eco, "scan", "{target}"), needs_network=False)
        proc = runner.run_tool(call, target, mode, report)
        if proc is None:
            report.cover(eco, "heuristics", "skipped (guarddog unavailable)")
            continue
        output = proc.stdout + proc.stderr
        match = re.search(r"(\d+) risks? detected", output)
        if not match:
            report.tool_notes.append(f"guarddog {eco}: could not read result (exit {proc.returncode})")
            report.cover(eco, "heuristics", "error")
            continue
        count = int(match.group(1))
        if count:
            report.add("warn", "tool", f"guarddog ({eco}): {count} suspicious heuristic(s) matched")
            report.tool_notes.append(f"guarddog {eco} output (tail):\n{output[-1500:]}")
            report.cover(eco, "heuristics", f"{count} flagged")
        else:
            report.cover(eco, "heuristics", "no risks detected")


def check_source_patterns(target: Path, report: Report) -> None:
    for path in iter_files(target):
        if path.suffix != ".py":
            continue
        rel = path.relative_to(target)
        if path.stat().st_size > MAX_SOURCE_BYTES:
            report.tool_notes.append(f"{rel}: larger than {MAX_SOURCE_BYTES} bytes; not pattern-checked")
            continue
        text = path.read_text(errors="replace")
        for pattern, label in INSTALL_TIME_PATTERNS.items():
            if re.search(pattern, text):
                report.add("warn", "static", f"{rel}: {label}")


def run_static_checks(target: Path, mode: str, report: Report) -> None:
    check_known_vulnerabilities(target, mode, report)
    check_heuristics(target, mode, report)
    if (target / "setup.py").exists():
        report.add("info", "static", "setup.py present: arbitrary code runs at install time")
    check_source_patterns(target, report)
