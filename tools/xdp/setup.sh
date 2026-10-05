#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: sudo tools/xdp/setup.sh INTERFACE PIN_DIR" >&2
  exit 2
fi

device=$1
pin_dir=$2
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ -e $pin_dir ]]; then
  echo "pin directory already exists: $pin_dir" >&2
  exit 1
fi

mkdir -p "$pin_dir"
object=$(mktemp /tmp/nyxr-bpf.XXXXXX)
trap 'rm -f "$object" "$pin_dir/program" "$pin_dir/xsks" "$pin_dir/filter"; rmdir "$pin_dir" 2>/dev/null || true' ERR
arch_include="/usr/include/$(gcc -dumpmachine)"
clang -O2 -g -target bpf -I "$arch_include" -c "$source_dir/nyxr.bpf.c" -o "$object"
bpftool prog load "$object" "$pin_dir/program" type xdp pinmaps "$pin_dir"
ip link set dev "$device" xdp pinned "$pin_dir/program"
rm "$object"
trap - ERR
echo "AF_XDP program attached to $device; maps pinned in $pin_dir"
