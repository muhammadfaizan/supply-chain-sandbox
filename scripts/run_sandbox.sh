#!/usr/bin/env bash
# Run the sandbox image against one candidate package directory.
#
# Isolation applied here (see README "Isolation layers"):
#   --network none         no egress at all; connection attempts fail and are logged
#   --read-only            root filesystem is immutable
#   --tmpfs /tmp, /work    the only writable locations, size-capped
#   --cap-drop=ALL         no Linux capabilities
#   no-new-privileges      setuid binaries cannot escalate
#   --user 10001           unprivileged user, no host UID mapping
#   --pids-limit/--memory  bounded resource use
#   --mount ...,readonly   candidate source mounted read-only; no other host paths
set -euo pipefail

PKG="${1:?usage: run_sandbox.sh <package-dir>}"
IMAGE="${SANDBOX_IMAGE:-supply-chain-sandbox:latest}"
PKG_ABS="$(cd "$PKG" && pwd)"

exec docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,size=64m,mode=1777 \
  --tmpfs /work:rw,size=256m,uid=10001,gid=10001 \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1 \
  --user 10001:10001 \
  -e PIP_NO_CACHE_DIR=1 \
  --mount "type=bind,source=$PKG_ABS,target=/input,readonly" \
  "$IMAGE" /input
