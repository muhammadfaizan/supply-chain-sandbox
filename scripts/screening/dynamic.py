"""Dynamic stage: install a Python package in the sandbox and judge what it did.

The host side has three parts:
  run_sandbox()   starts scripts/run_sandbox.sh and collects its output
  parse_output()  pulls the pip exit code and the event lines out of that output
  judge_events()  turns events into findings (pure function, unit-tested)

Failure is closed: if the sandbox output is missing its markers, the result is a
block, not a pass.
"""
import json
import os
import re
from pathlib import Path

from .models import Report
from .runner import run

ROOT = Path(__file__).resolve().parents[2]
RUN_SANDBOX = ROOT / "scripts" / "run_sandbox.sh"

# Events that mean the package reached outside its box: always a block.
BLOCKING_EVENTS = {"network_connect", "dns_lookup", "sensitive_file_access"}
# Writes outside the work folder: suspicious, but not proof of harm.
WARN_EVENTS = {"write_outside_workdir"}
# Routine build tooling spawns these (platform detection, sub-interpreters).
EXPECTED_SPAWNS = {"uname", "lsb_release", "python", "python3", "python3.13"}

_PIP_EXIT = re.compile(r"::PIP_EXIT::(\d+)")
_EVENTS = re.compile(r"::EVENTS_BEGIN::\n(.*?)::EVENTS_END::", re.S)


def can_install(target: Path) -> bool:
    return (target / "setup.py").exists() or (target / "pyproject.toml").exists()


def parse_output(stdout: str):
    """Return (pip_exit, events, malformed_lines, has_markers).

    pip_exit is None when the marker is missing. malformed_lines counts event
    lines that are not valid JSON, so they can be reported instead of dropped.
    """
    pip = _PIP_EXIT.search(stdout)
    body = _EVENTS.search(stdout)
    events, malformed = [], 0
    if body:
        for line in body.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                malformed += 1
    pip_exit = int(pip.group(1)) if pip else None
    return pip_exit, events, malformed, bool(body)


def judge_events(events: list) -> list:
    """Return (severity, message) pairs for the runtime events."""
    verdicts = []
    for ev in events:
        kind = ev.get("kind")
        if kind in BLOCKING_EVENTS:
            detail = ev.get("address") or ev.get("host") or ev.get("path")
            verdicts.append(("block", f"{kind}: {detail}"))
        elif kind in WARN_EVENTS:
            verdicts.append(("warn", f"{kind}: {ev.get('path')}"))
        elif kind == "process_spawn":
            name = Path(str(ev.get("args", "")).split(" ")[0]).name
            if name not in EXPECTED_SPAWNS:
                verdicts.append(("warn", f"unexpected process spawn: {ev.get('args')}"))
    return verdicts


def run_sandbox(target: Path, image: str, report: Report) -> None:
    env = {"SANDBOX_IMAGE": image,
           "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
           "HOME": os.environ.get("HOME", "/")}  # Docker CLI reads its config from HOME
    proc = run([str(RUN_SANDBOX), str(target)], env=env)

    pip_exit, events, malformed, has_markers = parse_output(proc.stdout)
    if not has_markers:
        report.add("block", "dynamic",
                   f"sandbox produced no monitor output (exit {proc.returncode}): "
                   f"{proc.stderr[-300:].strip()}")
        return

    report.install_exit = pip_exit
    report.events = events
    if malformed:
        report.add("warn", "dynamic", f"{malformed} monitor line(s) could not be read")
    for severity, message in judge_events(events):
        report.add(severity, "dynamic", message)
    if pip_exit not in (None, 0):
        report.add("warn", "dynamic", f"install exited with status {pip_exit}")
