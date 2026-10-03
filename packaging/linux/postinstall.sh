#!/bin/sh
# Create the nyxr system account and register the packetd unit.
# The unit is not enabled: it needs NYXR_PACKETD_INTERFACES set first.
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/nyxr.conf || true
fi
if ! getent group nyxr >/dev/null 2>&1; then
  groupadd --system nyxr
fi
if ! getent passwd nyxr >/dev/null 2>&1; then
  useradd --system --gid nyxr --no-create-home --home-dir / \
    --shell /usr/sbin/nologin --comment "nyxr packet relay" nyxr
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  # Restart a running relay so it picks up the new binary.
  systemctl try-restart nyxr-packetd.service >/dev/null 2>&1 || true
fi
