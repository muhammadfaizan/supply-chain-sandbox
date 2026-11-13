#!/bin/sh
# Runs inside the sandbox container. Usage: sandbox-install <package-dir>
# Copies the package to a writable location (the input mount is read-only),
# installs it with the monitor active, and prints the event log to stdout
# between markers so the host side can parse it.
set -eu

SRC_IN="${1:?usage: sandbox-install <package-dir>}"
WORK_SRC=/work/src
mkdir -p /work/site
cp -r "$SRC_IN" "$WORK_SRC"

set +e
pip install --no-deps --no-build-isolation --no-index \
    --target /work/site "$WORK_SRC" >/tmp/pip.log 2>&1
PIP_EXIT=$?
set -e

echo "::PIP_EXIT::$PIP_EXIT"
echo "::EVENTS_BEGIN::"
[ -f "${SANDBOX_EVENT_LOG:-/tmp/events.jsonl}" ] && cat "${SANDBOX_EVENT_LOG:-/tmp/events.jsonl}" || true
echo "::EVENTS_END::"
exit 0
