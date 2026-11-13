#!/usr/bin/env bash
# Scripted walkthrough used to record docs/demo-scan.gif.
# It runs the real commands; only the pauses and command echo are added for readability.
set -u
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/bin:$PATH"

run() {
  printf '\n\033[1;32m$\033[0m %s\n' "$1"
  sleep 1
  eval "$1"
  sleep 2
}

run "npm run scan"
run "npm run scan -- fixtures/malicious-pkg"
run "grep -E '^- \*\*(BLOCK|WARN)' reports/malicious-pkg.md | head -n 4"
