"""Runtime monitor loaded into every Python process in the sandbox.

Uses sys.addaudithook, which the interpreter calls for security-relevant
operations (socket connects, file opens, subprocess spawns). The hook runs
inside the same process as the package being installed, so it sees what the
package does without the package's cooperation. A package that deliberately
disables audit hooks in its own process could evade this; the container
limits (no network, read-only root, no secrets) are the backstop for that case.
"""
import json
import os
import sys
import threading

EVENT_LOG = os.environ.get("SANDBOX_EVENT_LOG", "/tmp/events.jsonl")
SENSITIVE_MARKERS = ("/.env", "/.ssh/", "/.aws/", "/etc/shadow", "/.netrc", "/.gnupg/")
WORK_ROOTS = ("/work/", "/tmp/", "/usr/", "/opt/monitor/")

_local = threading.local()


def _emit(record):
    # Guard against recursion: writing the log itself fires "open" events.
    if getattr(_local, "busy", False):
        return
    _local.busy = True
    try:
        with open(EVENT_LOG, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass
    finally:
        _local.busy = False


def _hook(event, args):
    if event == "socket.connect":
        # args: (socket, address)
        _emit({"kind": "network_connect", "address": str(args[1])})
    elif event == "socket.getaddrinfo":
        _emit({"kind": "dns_lookup", "host": str(args[0])})
    elif event == "open":
        # Opening an existing file descriptor (an int) is not a path operation.
        if isinstance(args[0], int):
            return
        # Resolve relative paths against the process cwd so "build/x" inside
        # /work/src is recognized as work-directory output.
        path = os.path.abspath(str(args[0]))
        mode = str(args[1]) if len(args) > 1 and args[1] is not None else "r"
        if any(marker in path for marker in SENSITIVE_MARKERS):
            _emit({"kind": "sensitive_file_access", "path": path, "mode": mode})
        elif any(c in mode for c in "wax+") and not path.startswith(WORK_ROOTS):
            _emit({"kind": "write_outside_workdir", "path": path, "mode": mode})
    elif event in ("subprocess.Popen", "os.system", "os.exec"):
        _emit({"kind": "process_spawn", "event": event, "args": str(args[0])[:200]})


sys.addaudithook(_hook)
