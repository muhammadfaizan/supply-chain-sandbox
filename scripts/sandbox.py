#!/usr/bin/env python3
"""One command-line entry point for the sandbox.

    npm run doctor              check that everything needed is installed
    npm run build               build the sandbox image
    npm run test                run the test suite
    npm run scan                screen the two built-in examples
    npm run scan -- ../my-lib   screen your own package folder

The same commands work with make:  make scan   or   make scan TARGET=../my-lib

Standard library only, so it runs on Python 3.10+ with nothing to install.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCREEN = ROOT / "scripts" / "screen.py"
REPORTS = ROOT / "reports"
IMAGE = "supply-chain-sandbox:latest"
TOOLS_IMAGE = "supply-chain-tools:latest"

EXAMPLES = {
    ROOT / "fixtures" / "clean-pkg": "pass",        # expected verdict
    ROOT / "fixtures" / "malicious-pkg": "block",
}

# ---------- small output helpers ----------

def ok(msg):
    print(f"  [ok]      {msg}")

def missing(msg):
    print(f"  [missing] {msg}")

def optional(msg):
    print(f"  [skip]    {msg}")

def die(msg, code=2):
    print(f"\nerror: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------- environment checks ----------

def docker_state() -> str:
    """Return 'missing', 'stopped', or 'running'."""
    if not shutil.which("docker"):
        return "missing"
    probe = subprocess.run(["docker", "info"], capture_output=True)
    return "running" if probe.returncode == 0 else "stopped"


def image_present(name: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", name],
                          capture_output=True).returncode == 0


def image_exists() -> bool:
    return image_present(IMAGE)


def build_image() -> bool:
    print(f"Building the sandbox image ({IMAGE}). The first build takes a few minutes...")
    return subprocess.run(["docker", "build", "-t", IMAGE, str(ROOT)]).returncode == 0


def ensure_ready():
    """Make sure Docker is running and the image exists. Build it if needed."""
    state = docker_state()
    if state == "missing":
        die("Docker is not installed. Run `npm run doctor` for install steps.")
    if state == "stopped":
        die("Docker is installed but not running.\n"
            "  macOS:  colima start\n"
            "  Linux:  start the Docker service (for example `sudo systemctl start docker`)")
    if not image_exists():
        if not build_image():
            die("building the sandbox image failed; see the Docker output above")


# ---------- commands ----------

def cmd_doctor(_args) -> int:
    print("Checking your setup:\n")
    required_ok = True

    py = sys.version_info
    if py >= (3, 10):
        ok(f"Python {py.major}.{py.minor}")
    else:
        missing(f"Python {py.major}.{py.minor} (need 3.10 or newer)")
        required_ok = False

    state = docker_state()
    if state == "missing":
        missing("Docker is not installed (macOS: `brew install colima docker`)")
        required_ok = False
    elif state == "stopped":
        missing("Docker is installed but not running (macOS: `colima start`)")
        required_ok = False
    else:
        ok("Docker is running")
        if image_exists():
            ok(f"sandbox image built ({IMAGE})")
        else:
            missing("sandbox image not built yet (run `npm run build`, or `npm run scan` builds it for you)")

    for tool, hint in [
        ("osv-scanner", "brew install osv-scanner"),
        ("guarddog", "pipx install --python /opt/homebrew/bin/python3.13 guarddog"),
    ]:
        if shutil.which(tool):
            ok(f"{tool} installed locally")
        elif docker_state() == "running" and image_present(TOOLS_IMAGE):
            ok(f"{tool} not installed locally; the scanner toolbox image will run it in Docker")
        else:
            optional(f"{tool} not installed locally; scans run it in Docker "
                     f"(built on first scan). Local install: {hint}")

    print()
    if required_ok:
        print("All required tools are ready. Try: npm run scan")
        return 0
    print("Fix the items marked [missing], then run `npm run doctor` again.")
    return 1


def build_tools_image() -> bool:
    print(f"Building the scanner toolbox image ({TOOLS_IMAGE})...")
    return subprocess.run(["docker", "build", "-f", str(ROOT / "Dockerfile.tools"),
                           "-t", TOOLS_IMAGE, str(ROOT)]).returncode == 0


def cmd_build(_args) -> int:
    if docker_state() != "running":
        ensure_ready()  # gives the right error message
    return 0 if (build_image() and build_tools_image()) else 1


def cmd_test(_args) -> int:
    ensure_ready()
    return subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                          cwd=ROOT).returncode


def top_findings(report: Path, limit: int = 4) -> list:
    if not report.exists():
        return []
    lines = [ln for ln in report.read_text().splitlines()
             if re.match(r"- \*\*(BLOCK|WARN)\*\*", ln)]
    return [re.sub(r"\*\*", "", ln[2:]) for ln in lines[:limit]]


def cmd_scan(args) -> int:
    ensure_ready()
    demo = not args.targets
    targets = list(EXAMPLES) if demo else [Path(t) for t in args.targets]

    results = []  # (name, verdict, report_path)
    for target in targets:
        path = target.expanduser().resolve()
        if not path.is_dir():
            die(f"not a folder: {target}")
        name = path.name
        report = REPORTS / f"{name}.md"

        cmd = [sys.executable, str(SCREEN), str(path), "--image", IMAGE, "--report", str(report)]
        if args.ecosystem:
            cmd += ["--ecosystem", args.ecosystem]
        if args.in_docker:
            cmd += ["--in-docker"]

        print(f"\nScanning {os.path.relpath(path)} ...")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        match = re.search(r"verdict: (\w+)", proc.stdout)
        verdict = match.group(1) if match else "error"
        if verdict == "error":
            print(proc.stdout + proc.stderr)
        results.append((name, verdict, report, path))

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    for name, verdict, report, path in results:
        print(f"\n{verdict.upper():<6} {name}")
        for line in top_findings(report):
            print(f"         - {line}")
        if report.exists():
            print(f"         full report: {os.path.relpath(report)}")

    if demo:
        # The examples are supposed to produce these verdicts. Matching them is success.
        all_as_expected = all(
            verdict == EXAMPLES[path.resolve()] for (_, verdict, _, path) in results)
        print("\nBuilt-in examples: " + ("both behaved as expected." if all_as_expected
                                         else "UNEXPECTED result, see above."))
        return 0 if all_as_expected else 1

    # Scanning your own code: BLOCK or an error fails the command, which suits CI.
    failed = any(verdict in ("block", "error") for _, verdict, _, _ in results)
    return 1 if failed else 0


# ---------- entry point ----------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sandbox", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check that everything needed is installed")
    sub.add_parser("build", help="build the sandbox image")
    sub.add_parser("test", help="run the test suite")
    scan = sub.add_parser("scan", help="screen the examples, or the folders you name")
    scan.add_argument("targets", nargs="*",
                      help="folders to screen (default: the two built-in examples)")
    scan.add_argument("--ecosystem", default=None,
                      help="only check these: pypi, npm, rubygems, go (comma-separated)")
    scan.add_argument("--in-docker", action="store_true",
                      help="run OSV-Scanner and GuardDog in the toolbox container")

    args = parser.parse_args()
    handlers = {"doctor": cmd_doctor, "build": cmd_build, "test": cmd_test, "scan": cmd_scan}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
