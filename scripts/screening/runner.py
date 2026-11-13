"""Run external scanners (OSV-Scanner, GuardDog) on a target folder.

Two modes:
  docker  (default when Docker is running) runs each tool in the toolbox image,
          with the target mounted read-only.
  local   runs the tools installed on this machine. Only used with --local-tools,
          or when Docker is not available.

Every tool run reports what happened in report.tool_notes, so a skipped tool is
visible in the report and never silently treated as a clean result.
"""
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .models import Report

ROOT = Path(__file__).resolve().parents[2]
TOOLBOX_DOCKERFILE = ROOT / "Dockerfile.tools"
TOOLS_IMAGE = "supply-chain-tools:latest"
TARGET_IN_CONTAINER = "/target"
PLACEHOLDER = "{target}"


@dataclass(frozen=True)
class ToolCall:
    name: str            # executable name, e.g. "guarddog"
    args: tuple          # arguments; "{target}" is replaced with the folder path
    needs_network: bool  # OSV-Scanner downloads its vulnerability database; GuardDog does not


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def docker_running() -> bool:
    return shutil.which("docker") is not None and run(["docker", "info"]).returncode == 0


def choose_mode(local_tools: bool) -> str:
    """Return 'docker' or 'local' for the whole run."""
    if local_tools:
        return "local"
    return "docker" if docker_running() else "local"


def ensure_toolbox_image() -> bool:
    if run(["docker", "image", "inspect", TOOLS_IMAGE]).returncode == 0:
        return True
    print(f"Building the scanner toolbox image ({TOOLS_IMAGE}), one time only...",
          file=sys.stderr)
    build = run(["docker", "build", "-f", str(TOOLBOX_DOCKERFILE), "-t", TOOLS_IMAGE, str(ROOT)])
    return build.returncode == 0


def docker_command(call: ToolCall, target: Path) -> list:
    """Build the hardened `docker run` command for one tool call.

    --mount (not -v) so a colon or comma in the folder name cannot change which
    host path is mounted. The network is off unless the tool needs it.
    """
    network = [] if call.needs_network else ["--network", "none"]
    args = [a.replace(PLACEHOLDER, TARGET_IN_CONTAINER) for a in call.args]
    return ["docker", "run", "--rm", *network,
            "--read-only", "--tmpfs", "/tmp:rw,size=256m",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "512m",
            "--user", "10001:10001",
            "--mount", f"type=bind,source={target},target={TARGET_IN_CONTAINER},readonly",
            "--entrypoint", call.name, TOOLS_IMAGE, *args]


def run_tool(call: ToolCall, target: Path, mode: str, report: Report):
    """Run one tool call. Returns the CompletedProcess, or None if it could not run."""
    if mode == "local":
        if not shutil.which(call.name):
            report.tool_notes.append(f"{call.name}: not installed locally; skipped")
            return None
        report.tool_notes.append(f"{call.name}: ran locally")
        args = [a.replace(PLACEHOLDER, str(target)) for a in call.args]
        return run([call.name, *args])

    # Docker mode. A comma in the path would break the --mount option, so refuse it.
    if "," in str(target):
        report.tool_notes.append(f"{call.name}: folder name contains a comma; "
                                 "cannot mount it in Docker; skipped")
        return None
    if not docker_running():
        report.tool_notes.append(f"{call.name}: Docker is not running; skipped")
        return None
    if not ensure_toolbox_image():
        report.tool_notes.append(f"{call.name}: toolbox image could not be built; skipped")
        return None
    report.tool_notes.append(f"{call.name}: ran in Docker ({TOOLS_IMAGE})")
    return run(docker_command(call, target))
