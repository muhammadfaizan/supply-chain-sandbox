"""Command-line entry point: wires the stages together and sets the exit code.

Exit codes: 0 pass or warn, 1 block, 2 usage or setup error.
"""
import argparse
import sys
from pathlib import Path

from . import checks, dynamic, runner
from .detect import ECOSYSTEMS, detect_ecosystems
from .models import Report
from .report import write_report

DEFAULT_IMAGE = "supply-chain-sandbox:latest"


def parse_ecosystems(value: str) -> set:
    chosen = {v.strip().lower() for v in value.split(",") if v.strip()}
    unknown = chosen - set(ECOSYSTEMS)
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown ecosystem(s): {', '.join(sorted(unknown))} "
            f"(choose from {', '.join(ECOSYSTEMS)})")
    return chosen


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="screen.py",
        description="Screen a folder's dependencies. Exit 0 = pass/warn, 1 = block, 2 = error.")
    p.add_argument("target", type=Path, help="folder to screen")
    p.add_argument("--ecosystem", default=set(), type=parse_ecosystems,
                   help=f"only screen these, comma-separated ({', '.join(ECOSYSTEMS)}). "
                        "Default: detect automatically")
    p.add_argument("--image", default=DEFAULT_IMAGE,
                   help="sandbox image to install packages in")
    p.add_argument("--report", type=Path, default=Path("report.md"),
                   help="where to write the Markdown report")
    p.add_argument("--skip-dynamic", action="store_true",
                   help="do not install anything in the sandbox")
    p.add_argument("--local-tools", action="store_true",
                   help="use OSV-Scanner and GuardDog installed on this machine instead of "
                        "the Docker toolbox (the toolbox is the default and safer choice)")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if not args.target.is_dir():
        print(f"error: {args.target} is not a folder", file=sys.stderr)
        return 2
    target = args.target.resolve()

    detected = detect_ecosystems(target)
    if args.ecosystem:
        detected = {eco: files for eco, files in detected.items() if eco in args.ecosystem}
        if not detected:
            print(f"error: no {', '.join(sorted(args.ecosystem))} files found in {args.target}",
                  file=sys.stderr)
            return 2
    if not detected:
        print(f"error: no supported dependency files found in {args.target} "
              f"(looked for {', '.join(ECOSYSTEMS)})", file=sys.stderr)
        return 2

    report = Report(target=str(args.target), ecosystems=detected)
    for eco in detected:
        report.coverage[eco] = {}

    mode = runner.choose_mode(args.local_tools)
    report.tool_notes.append(f"tool mode: {mode}")
    checks.run_static_checks(target, mode, report)

    if args.skip_dynamic:
        report.tool_notes.append("dynamic install skipped (--skip-dynamic)")
    elif "pypi" in detected and dynamic.can_install(target):
        dynamic.run_sandbox(target, args.image, report)
        report.cover("pypi", "install in sandbox", "ran")
    else:
        report.tool_notes.append(
            "no Python package to install in the sandbox; "
            "npm, RubyGems and Go were screened statically only")

    report.dedupe()
    write_report(report, args.report)
    print(f"ecosystems: {', '.join(sorted(detected))}")
    print(f"verdict: {report.verdict}  (report: {args.report})")
    return 1 if report.verdict == "block" else 0
