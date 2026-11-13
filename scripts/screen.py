#!/usr/bin/env python3
"""Screen a folder of dependencies before they are trusted.

Supported ecosystems (detected automatically from the files present):
  pypi      requirements*.txt, setup.py, pyproject.toml, Pipfile.lock, poetry.lock
  npm       package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
  rubygems  Gemfile, Gemfile.lock, *.gemspec
  go        go.mod, go.sum

Stages:
  1. Known vulnerabilities (OSV-Scanner, all ecosystems in one pass).
  2. Malicious-package heuristics (GuardDog, one run per detected ecosystem).
  3. Source scan for install-time code patterns (Python files only).
  4. Install in the sandbox and watch what it does (Python packages with setup.py
     or pyproject.toml only; other ecosystems are screened statically).
  5. Gate: pass / warn / block, written to a Markdown report.

Exit code: 0 for pass or warn, 1 for block, 2 for usage or tool errors.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RUN_SANDBOX = HERE / "run_sandbox.sh"
TOOLS_IMAGE = "supply-chain-tools:latest"  # built from Dockerfile.tools

ECOSYSTEMS = ("pypi", "npm", "rubygems", "go")
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv",
             "__pycache__", "build", "dist"}
OSV_NAMES = {"PyPI": "pypi", "npm": "npm", "Go": "go", "RubyGems": "rubygems"}

INSTALL_TIME_PATTERNS = {
    r"\bsocket\.": "raw socket use",
    r"\burllib|\brequests\.|\bhttpx\.|\bhttp\.client": "outbound HTTP client",
    r"\bsubprocess\.|\bos\.system\(|\bos\.popen\(": "process spawn",
    r"\bbase64\.b64decode|\bexec\(|\beval\(": "decode-and-execute pattern",
    r"~/\.(ssh|aws|netrc|env)|\.ssh/|\.aws/": "credential path reference",
}

BLOCKING_EVENTS = {"network_connect", "dns_lookup", "sensitive_file_access"}
WARN_EVENTS = {"write_outside_workdir"}
# Routine build tooling spawns these (platform detection, sub-interpreters).
EXPECTED_SPAWNS = {"uname", "lsb_release", "python", "python3", "python3.13"}


@dataclass
class Finding:
    severity: str  # "block" | "warn" | "info"
    stage: str     # "static" | "dynamic" | "tool"
    message: str


@dataclass
class Report:
    target: str
    ecosystems: dict = field(default_factory=dict)   # eco -> [manifest paths]
    coverage: dict = field(default_factory=dict)     # eco -> {check: status}
    findings: list = field(default_factory=list)
    install_exit: int | None = None
    events: list = field(default_factory=list)
    tool_notes: list = field(default_factory=list)

    @property
    def verdict(self) -> str:
        sev = {f.severity for f in self.findings}
        if "block" in sev:
            return "block"
        if "warn" in sev:
            return "warn"
        return "pass"


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


# ---------- detection ----------

def classify(name: str):
    """Map a file name to the ecosystem it describes, or None."""
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pypi"
    if name in {"setup.py", "setup.cfg", "pyproject.toml", "Pipfile.lock", "poetry.lock"}:
        return "pypi"
    if name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
        return "npm"
    if name in {"Gemfile", "Gemfile.lock"} or name.endswith(".gemspec"):
        return "rubygems"
    if name in {"go.mod", "go.sum"}:
        return "go"
    return None


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def detect_ecosystems(root: Path) -> dict:
    found = {}
    for path in iter_files(root):
        eco = classify(path.name)
        if eco:
            found.setdefault(eco, []).append(str(path.relative_to(root)))
    return found


# ---------- static stage ----------

def docker_running() -> bool:
    return shutil.which("docker") is not None and run(["docker", "info"]).returncode == 0


def ensure_tools_image() -> bool:
    if run(["docker", "image", "inspect", TOOLS_IMAGE]).returncode == 0:
        return True
    print(f"Building the scanner toolbox image ({TOOLS_IMAGE}), one time only...",
          file=sys.stderr)
    build = run(["docker", "build", "-f", str(ROOT / "Dockerfile.tools"),
                 "-t", TOOLS_IMAGE, str(ROOT)])
    return build.returncode == 0


def run_tool(tool: str, args: list, target: Path, in_docker: bool, report: Report):
    """Run an external scanner on `target`, read-only.

    Uses the locally installed tool when there is one. Otherwise, or when
    in_docker is set, runs it inside the toolbox image. Returns the
    CompletedProcess, or None if the tool could not be run at all.
    The placeholder {target} in args is replaced with the folder path.
    """
    if not in_docker and shutil.which(tool):
        report.tool_notes.append(f"{tool}: ran locally")
        return run([tool, *[a.replace("{target}", str(target)) for a in args]])

    if not docker_running():
        report.tool_notes.append(f"{tool}: not installed locally and Docker is not running; skipped")
        return None
    if not ensure_tools_image():
        report.tool_notes.append(f"{tool}: toolbox image could not be built; skipped")
        return None

    cmd = ["docker", "run", "--rm",
           "--read-only", "--tmpfs", "/tmp:rw,size=256m",
           "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
           "--user", "10001:10001",
           "-v", f"{target}:/target:ro",
           "--entrypoint", tool, TOOLS_IMAGE,
           *[a.replace("{target}", "/target") for a in args]]
    report.tool_notes.append(f"{tool}: ran in Docker ({TOOLS_IMAGE})")
    return run(cmd)


def check_known_vulnerabilities(target: Path, selected: set, report: Report, in_docker: bool) -> None:
    proc = run_tool("osv-scanner", ["scan", "source", "-r", "{target}",
                                    "--allow-no-lockfiles", "--format", "json"],
                    target, in_docker, report)
    if proc is None:
        for eco in report.ecosystems:
            report.coverage[eco]["known vulnerabilities"] = "skipped (osv-scanner unavailable)"
        return
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        report.tool_notes.append(f"osv-scanner output not parseable (exit {proc.returncode})")
        return

    checked = {eco: 0 for eco in report.ecosystems}
    for result in data.get("results", []):
        for entry in result.get("packages", []):
            pkg = entry.get("package", {})
            eco = OSV_NAMES.get(pkg.get("ecosystem", "").split(":")[0])
            if eco is None or (selected and eco not in selected):
                continue
            checked[eco] = checked.get(eco, 0) + 1
            vulns = entry.get("vulnerabilities", [])
            if vulns:
                ids = [v.get("id", "?") for v in vulns]
                report.findings.append(Finding(
                    "warn", "static",
                    f"{pkg.get('name')} {pkg.get('version')} ({eco}): "
                    f"{len(vulns)} known vulnerabilities, e.g. {', '.join(ids[:3])}"))

    for eco in report.ecosystems:
        if eco in checked:
            n = checked[eco]
            report.coverage[eco]["known vulnerabilities"] = f"checked {n} package{'s' if n != 1 else ''}"


def check_heuristics(target: Path, ecos: list, report: Report, in_docker: bool) -> None:
    for eco in ecos:
        proc = run_tool("guarddog", [eco, "scan", "{target}"], target, in_docker, report)
        if proc is None:
            report.coverage[eco]["heuristics"] = "skipped (guarddog unavailable)"
            continue
        output = proc.stdout + proc.stderr
        match = re.search(r"(\d+) risks? detected", output)
        if not match:
            report.tool_notes.append(f"guarddog {eco}: could not read result (exit {proc.returncode})")
            report.coverage[eco]["heuristics"] = "error"
            continue
        count = int(match.group(1))
        if count:
            report.findings.append(Finding(
                "warn", "tool", f"guarddog ({eco}): {count} suspicious heuristic(s) matched"))
            report.tool_notes.append(f"guarddog {eco} output (tail):\n{output[-1500:]}")
            report.coverage[eco]["heuristics"] = f"{count} flagged"
        else:
            report.coverage[eco]["heuristics"] = "no risks detected"


def check_source_patterns(target: Path, report: Report) -> None:
    for py in sorted(target.rglob("*.py")):
        if any(part in SKIP_DIRS for part in py.relative_to(target).parts):
            continue
        text = py.read_text(errors="replace")
        for pattern, label in INSTALL_TIME_PATTERNS.items():
            if re.search(pattern, text):
                report.findings.append(Finding(
                    "warn", "static", f"{py.relative_to(target)}: {label}"))


def static_stage(target: Path, selected: set, report: Report, in_docker: bool) -> None:
    check_known_vulnerabilities(target, selected, report, in_docker)
    check_heuristics(target, sorted(report.ecosystems), report, in_docker)

    if (target / "setup.py").exists():
        report.findings.append(Finding(
            "info", "static", "setup.py present: arbitrary code runs at install time"))
    check_source_patterns(target, report)


# ---------- dynamic stage (Python packages only) ----------

def can_install_in_sandbox(target: Path) -> bool:
    return (target / "setup.py").exists() or (target / "pyproject.toml").exists()


def dynamic_check(target: Path, image: str, report: Report) -> None:
    proc = run([str(RUN_SANDBOX), str(target)],
               env={"SANDBOX_IMAGE": image,
                    "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})
    out = proc.stdout
    if proc.returncode != 0 and "::EVENTS_BEGIN::" not in out:
        report.findings.append(Finding(
            "block", "dynamic",
            f"sandbox run failed (exit {proc.returncode}): {proc.stderr[-300:]}"))
        return

    m = re.search(r"::PIP_EXIT::(\d+)", out)
    report.install_exit = int(m.group(1)) if m else None
    body = re.search(r"::EVENTS_BEGIN::\n(.*?)::EVENTS_END::", out, re.S)
    for line in (body.group(1).splitlines() if body else []):
        line = line.strip()
        if not line:
            continue
        try:
            report.events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    for ev in report.events:
        kind = ev.get("kind")
        if kind in BLOCKING_EVENTS:
            detail = ev.get("address") or ev.get("host") or ev.get("path")
            report.findings.append(Finding("block", "dynamic", f"{kind}: {detail}"))
        elif kind in WARN_EVENTS:
            report.findings.append(Finding("warn", "dynamic", f"{kind}: {ev.get('path')}"))
        elif kind == "process_spawn":
            name = Path(str(ev.get("args", "")).split(" ")[0]).name
            if name not in EXPECTED_SPAWNS:
                report.findings.append(Finding(
                    "warn", "dynamic", f"unexpected process spawn: {ev.get('args')}"))

    if report.install_exit not in (None, 0):
        report.findings.append(Finding(
            "warn", "dynamic", f"install exited with status {report.install_exit}"))


# ---------- report ----------

def write_report(report: Report, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# Dependency screening report",
        "",
        f"- Target: `{report.target}`",
        f"- Generated: {stamp}",
        f"- **Verdict: {report.verdict.upper()}**",
    ]
    if report.install_exit is not None:
        lines.append(f"- Install exit code: {report.install_exit}")

    lines += ["", "## Coverage", "",
              "| Ecosystem | Manifests found | Known vulnerabilities | Heuristics | Install in sandbox |",
              "|---|---|---|---|---|"]
    for eco in sorted(report.ecosystems):
        cov = report.coverage.get(eco, {})
        if eco == "pypi":
            default = "skipped: no setup.py or pyproject.toml to install"
        else:
            default = "not supported yet (static only)"
        install = cov.get("install in sandbox", default)
        manifests = ", ".join(f"`{m}`" for m in report.ecosystems[eco][:4])
        lines.append(f"| {eco} | {manifests} | {cov.get('known vulnerabilities', 'n/a')} "
                     f"| {cov.get('heuristics', 'n/a')} | {install} |")
    if not report.ecosystems:
        lines.append("| - | none | - | - | - |")

    lines += ["", "## Findings"]
    if report.findings:
        lines += [f"- **{f.severity.upper()}** ({f.stage}) {f.message}"
                  for f in report.findings]
    else:
        lines.append("- None")
    lines += ["", "## Runtime events", ""]
    lines += ([f"- `{json.dumps(e)}`" for e in report.events] or ["- None"])
    lines += ["", "## Tool notes", ""]
    lines += ([f"```\n{n}\n```" for n in report.tool_notes] or ["- None"])
    out.write_text("\n".join(lines) + "\n")


# ---------- main ----------

def parse_ecosystems(value: str | None) -> set:
    if not value:
        return set()
    chosen = {v.strip().lower() for v in value.split(",") if v.strip()}
    unknown = chosen - set(ECOSYSTEMS)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown ecosystem(s): {', '.join(sorted(unknown))} "
            f"(choose from {', '.join(ECOSYSTEMS)})")
    return chosen


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", type=Path, help="folder to screen")
    p.add_argument("--ecosystem", default=None, type=parse_ecosystems,
                   help="only screen these ecosystems, comma-separated "
                        f"({', '.join(ECOSYSTEMS)}). Default: detect automatically")
    p.add_argument("--image", default="supply-chain-sandbox:latest")
    p.add_argument("--report", type=Path, default=Path("report.md"))
    p.add_argument("--skip-dynamic", action="store_true",
                   help="do not install anything in the sandbox")
    p.add_argument("--in-docker", action="store_true",
                   help="run OSV-Scanner and GuardDog in the toolbox container even if "
                        "they are installed locally")
    args = p.parse_args()

    if not args.target.is_dir():
        print(f"error: {args.target} is not a folder", file=sys.stderr)
        return 2

    target = args.target.resolve()
    report = Report(target=str(args.target))
    detected = detect_ecosystems(target)
    selected = args.ecosystem or set()
    if selected:
        detected = {eco: files for eco, files in detected.items() if eco in selected}
        if not detected:
            print(f"error: no {', '.join(sorted(selected))} files found in {args.target}",
                  file=sys.stderr)
            return 2
    if not detected:
        print(f"error: no supported dependency files found in {args.target} "
              f"(looked for {', '.join(ECOSYSTEMS)})", file=sys.stderr)
        return 2

    report.ecosystems = detected
    for eco in detected:
        report.coverage[eco] = {}

    static_stage(target, selected, report, args.in_docker)

    if args.skip_dynamic:
        report.tool_notes.append("dynamic install skipped (--skip-dynamic)")
    elif "pypi" in detected and can_install_in_sandbox(target):
        dynamic_check(target, args.image, report)
        for eco in detected:
            if eco == "pypi":
                report.coverage[eco]["install in sandbox"] = "ran"
    else:
        report.tool_notes.append(
            "no Python package to install in the sandbox; "
            "npm, RubyGems and Go were screened statically only")

    # Drop duplicate findings: pip runs setup.py more than once (metadata, then wheel).
    seen, unique = set(), []
    for f in report.findings:
        key = (f.severity, f.stage, f.message)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    report.findings = unique

    write_report(report, args.report)
    print(f"ecosystems: {', '.join(sorted(detected))}")
    print(f"verdict: {report.verdict}  (report: {args.report})")
    return 1 if report.verdict == "block" else 0


if __name__ == "__main__":
    sys.exit(main())
