#!/bin/sh
# Stop the relay on removal, not on upgrade.
#   deb: $1 = remove | upgrade | deconfigure ...
#   rpm: $1 = 0 on erase, >= 1 on upgrade
set -e

case "$1" in
  remove|0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now nyxr-packetd.service >/dev/null 2>&1 || true
    fi
    ;;
esac
