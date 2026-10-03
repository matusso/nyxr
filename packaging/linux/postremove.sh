#!/bin/sh
# The nyxr account is left in place so files it owns keep a valid owner.
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
