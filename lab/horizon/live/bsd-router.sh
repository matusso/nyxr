#!/bin/sh
# Operator-owned disposable FreeBSD VM only: one routed hop for the Windows
# routed study. setup/teardown run from the operator's root session; control
# runs only as an SSH forced command and accepts TRUTH, CLEAN, DROP. No dummynet:
# v1 shaping panicked this FreeBSD 15.1 ARM64 VM in its forwarding path.
set -eu
dir=/root/hz66-router
# setup records the explicit interface; control and teardown reuse it.
interface=$(cat "$dir/interface" 2>/dev/null || echo "${2:-}")
src4=10.66.21.1; hop4a=10.66.21.3; hop4b=10.66.22.3; dst4=10.66.22.2
src6=fd66:66:21::1; hop6a=fd66:66:21::3; hop6b=fd66:66:22::3; dst6=fd66:66:22::2
sysctls="net.inet.ip.forwarding net.inet6.ip6.forwarding net.inet.ip.redirect net.inet6.ip6.redirect"

snapshot() {
    echo "fixture=$(cat "$dir/fixture")"
    echo "condition=$(cat "$dir/condition")"
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "interface=$interface"
    echo "--- system"
    freebsd-version -kru
    sysctl kern.boottime hw.physmem $sysctls net.inet.ip.fw.enable net.inet6.ip6.fw.enable 2>&1
    echo "--- interface"
    ifconfig "$interface" 2>&1
    echo "--- ipfw"
    ipfw -a list 2>&1
    echo "--- modules"
    kldstat 2>&1
    echo "--- end"
}

shape() {
    ipfw -q delete 60066 60067 2>/dev/null || true
    case $1 in
    clean) ;;
    drop)
        ipfw -q add 60066 set 30 deny tcp from "$dst4" 443 to "$src4" out xmit "$interface" tcpflags syn,ack
        ipfw -q add 60067 set 30 deny tcp from "$dst6" 443 to "$src6" out xmit "$interface" tcpflags syn,ack ;;
    esac
    echo "$1" > "$dir/condition"
}

case ${1:-} in
setup)
    test "$(id -u)" = 0
    test ! -e "$dir"
    if kldstat -n ipfw >/dev/null 2>&1; then echo "Existing IPFW: refusing host changes" >&2; exit 1; fi
    ifconfig "$interface" > /dev/null
    mkdir -m 700 "$dir"
    echo "$interface" > "$dir/interface"
    { date -u; freebsd-version -kru; uname -a; kldstat; ifconfig "$interface"; netstat -rn
      sysctl $sysctls; kenv net.inet.ip.fw.default_to_accept 2>&1 || true; } > "$dir/host-before.txt" 2>&1
    sysctl -n $sysctls > "$dir/sysctls-before"
    kenv net.inet.ip.fw.default_to_accept > "$dir/kenv-before" 2>/dev/null || : > "$dir/kenv-before"
    # Load IPFW with an accept default so existing management traffic is unaffected.
    kenv net.inet.ip.fw.default_to_accept=1 > /dev/null
    : > "$dir/modules"
    kldload ipfw; echo ipfw >> "$dir/modules"
    test "$(ipfw list | grep -v '^65535 ' | wc -l | tr -d ' ')" = 0
    ipfw list | grep -q '65535 allow ip from any to any'
    ifconfig "$interface" inet "$hop4a/24" alias
    ifconfig "$interface" inet "$hop4b/24" alias
    ifconfig "$interface" inet6 "$hop6a/64" alias
    ifconfig "$interface" inet6 "$hop6b/64" alias
    sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 net.inet.ip.redirect=0 net.inet6.ip6.redirect=0 > /dev/null
    ipfw -q add 60064 set 30 count tcp from "$dst4" 443 to "$src4" out xmit "$interface" tcpflags syn,ack
    ipfw -q add 60065 set 30 count tcp from "$dst6" 443 to "$src6" out xmit "$interface" tcpflags syn,ack
    uuidgen > "$dir/fixture"
    shape clean
    snapshot ;;
control)
    # SSH_ORIGINAL_COMMAND is a fixed word; nothing from it is executed.
    request=${SSH_ORIGINAL_COMMAND:-}
    case $request in
    TRUTH) ;;
    CLEAN) shape clean ;;
    DROP) shape drop ;;
    *) echo "unregistered router control" >&2; exit 2 ;;
    esac
    snapshot ;;
teardown)
    test "$(id -u)" = 0
    test -d "$dir"
    set +e
    ipfw -q delete 60064 60065 60066 60067
    ifconfig "$interface" inet6 "$hop6b" -alias
    ifconfig "$interface" inet6 "$hop6a" -alias
    ifconfig "$interface" inet "$hop4b" -alias
    ifconfig "$interface" inet "$hop4a" -alias
    set -- $(cat "$dir/sysctls-before")
    sysctl net.inet.ip.forwarding="$1" net.inet6.ip6.forwarding="$2" net.inet.ip.redirect="$3" net.inet6.ip6.redirect="$4" > /dev/null
    for module in $(tail -r "$dir/modules"); do kldunload "$module"; done
    old=$(cat "$dir/kenv-before")
    if test -n "$old"; then kenv "net.inet.ip.fw.default_to_accept=$old" > /dev/null; else kenv -u net.inet.ip.fw.default_to_accept; fi
    { date -u; kldstat; ifconfig "$interface"; netstat -rn; sysctl $sysctls
      kenv net.inet.ip.fw.default_to_accept 2>&1; } > "$dir/host-after.txt" 2>&1
    cat "$dir/host-after.txt" ;;
*)
    echo "usage: $0 setup interface | control | teardown" >&2; exit 2 ;;
esac
