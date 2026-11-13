"""Tests for the sandbox. Requires Docker and a built image (`make build`).

Verdict tests exercise the full pipeline. Isolation tests run commands in a
container with the same hardening flags as scripts/run_sandbox.sh, and check
that each restriction actually holds.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "scripts"))  # lets tests import the screening package
IMAGE = os.environ.get("SANDBOX_IMAGE", "supply-chain-sandbox:latest")
SCREEN = PROJECT / "scripts" / "screen.py"
CLEAN = PROJECT / "fixtures" / "clean-pkg"
MALICIOUS = PROJECT / "fixtures" / "malicious-pkg"

HARDENING = [
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,size=64m,mode=1777",
    "--tmpfs", "/work:rw,size=256m,uid=10001,gid=10001",
    "--cap-drop=ALL",
    "--security-opt", "no-new-privileges:true",
    "--user", "10001:10001",
]


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def image_built() -> bool:
    return subprocess.run(["docker", "image", "inspect", IMAGE],
                          capture_output=True).returncode == 0


SKIP_REASON = "needs Docker running and the image built (`make build`)"


def in_sandbox(shell_cmd: str, extra: list | None = None):
    """Run a shell snippet in a hardened container and return CompletedProcess."""
    cmd = ["docker", "run", "--rm", *HARDENING, *(extra or []),
           "--entrypoint", "sh", IMAGE, "-c", shell_cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


@unittest.skipUnless(docker_available() and image_built(), SKIP_REASON)
class IsolationTests(unittest.TestCase):
    def test_no_network_egress(self):
        r = in_sandbox("python3 -c \"import socket; socket.create_connection(('1.1.1.1', 80), timeout=3)\"")
        self.assertNotEqual(r.returncode, 0, "connection should fail with no network")

    def test_root_filesystem_is_read_only(self):
        r = in_sandbox("touch /usr/local/bin/tampered")
        self.assertNotEqual(r.returncode, 0)

    def test_no_linux_capabilities(self):
        r = in_sandbox("grep CapEff /proc/self/status")
        self.assertEqual(r.returncode, 0)
        self.assertIn("0000000000000000", r.stdout)

    def test_runs_as_unprivileged_user(self):
        r = in_sandbox("id -u")
        self.assertEqual(r.stdout.strip(), "10001")

    def test_host_paths_not_visible(self):
        r = in_sandbox("test -e /Users && echo PRESENT || echo ABSENT; "
                       "test -e /home/muhammadfaizan && echo PRESENT || echo ABSENT")
        self.assertEqual(r.stdout.split(), ["ABSENT", "ABSENT"])

    def test_no_host_environment_leaks(self):
        r = in_sandbox("env")
        for leak in ("AWS_", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "ANTHROPIC_API_KEY"):
            self.assertNotIn(leak, r.stdout)


@unittest.skipUnless(docker_available() and image_built(), SKIP_REASON)
class VerdictTests(unittest.TestCase):
    def screen(self, target: Path) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            r = subprocess.run(
                [sys.executable, str(SCREEN), str(target), "--report", str(report)],
                capture_output=True, text=True, timeout=600)
            return r.returncode, report.read_text() if report.exists() else ""

    def test_clean_package_passes(self):
        code, report = self.screen(CLEAN)
        self.assertEqual(code, 0)
        self.assertIn("Verdict: PASS", report)

    def test_malicious_package_is_blocked(self):
        code, report = self.screen(MALICIOUS)
        self.assertEqual(code, 1)
        self.assertIn("Verdict: BLOCK", report)

    def test_malicious_network_attempt_is_logged(self):
        _, report = self.screen(MALICIOUS)
        self.assertIn("evil.example.test", report)
        self.assertIn("dns_lookup", report)

    def test_malicious_credential_read_is_logged(self):
        _, report = self.screen(MALICIOUS)
        self.assertIn("sensitive_file_access", report)
        self.assertIn("/.env", report)


class StaticOnlyTests(unittest.TestCase):
    """Runs without Docker: checks the static stage only."""

    def test_detects_all_four_ecosystems(self):
        from screening.detect import detect_ecosystems
        found = detect_ecosystems(PROJECT / "fixtures" / "multi-ecosystem")
        self.assertEqual(sorted(found), ["go", "npm", "pypi", "rubygems"])

    def test_static_stage_flags_socket_use_in_malicious_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            r = subprocess.run(
                [sys.executable, str(SCREEN), str(MALICIOUS),
                 "--skip-dynamic", "--report", str(report)],
                capture_output=True, text=True, timeout=120)
            text = report.read_text()
        self.assertIn("raw socket use", text)
        self.assertIn("credential path reference", text)
        self.assertNotEqual(r.returncode, 2, "usage/tool error")


if __name__ == "__main__":
    unittest.main()
