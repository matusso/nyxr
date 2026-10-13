#!/bin/sh
# Operator-owned disposable FreeBSD VM only. No packages, host firewall rules,
# forwarding, persistent config, or default route changes.
set -eu
test "$(id -u)" = 0
base=$(mktemp -d /tmp/nyxr-hz66-vnet.XXXXXX)
chmod 700 "$base"
bridge=
epairs=
jails=
mounts=
modules=
pids=
kenv_changed=0
old_kenv=$(kenv net.inet.ip.fw.default_to_accept 2>/dev/null || true)
upload() {
    file=$1
    route=$2
    bytes=$(wc -c < "$file" | tr -d ' ')
    { printf 'POST %s HTTP/1.0\r\nHost: 192.168.254.1\r\nContent-Length: %s\r\n\r\n' "$route" "$bytes"; cat "$file"; } |
        nc -N -w 10 192.168.254.1 18066
}
cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    for pid in $pids; do kill -TERM "$pid" 2>/dev/null; done
    for pid in $pids; do wait "$pid" 2>/dev/null; done
    for name in $jails; do jail -r "$name"; done
    for path in $mounts; do umount "$path"; done
    if test -n "$bridge"; then ifconfig "$bridge" deletem em0; ifconfig "$bridge" destroy; fi
    for pair in $epairs; do ifconfig "$pair" destroy; done
    for module in $modules; do kldunload "$module"; done
    if test "$kenv_changed" = 1; then
        if test -n "$old_kenv"; then kenv "net.inet.ip.fw.default_to_accept=$old_kenv"; else kenv -u net.inet.ip.fw.default_to_accept; fi
    fi
    { date -u; jls; kldstat; ifconfig em0; netstat -rn; sysctl hw.physmem kern.boottime net.inet.tcp.sack.enable; mount; } > "$base/host-after.txt" 2>&1
    echo "setup_exit_status=$status" > "$base/status.txt"
    tar -czf "$base/artifacts.tar.gz" -C "$base" host-before.txt host-after.txt setup.log status.txt \
        endpoint.c endpoint compiler.log delay-profile.txt development reserved 2>/dev/null
    upload "$base/artifacts.tar.gz" /guest-artifacts
    echo "BSD VNET study stopped; evidence retained in $base"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
{ date -u; freebsd-version -kru; uname -a; jls; kldstat; ifconfig; netstat -rn; sysctl hw.physmem kern.boottime net.inet.tcp.sack.enable; kenv net.inet.ip.fw.default_to_accept 2>/dev/null || true; mount; } > "$base/host-before.txt" 2>&1
# Refuse a non-disposable environment with existing jails or host IPFW.
test "$(jls jid | wc -l | tr -d ' ')" = 0
if kldstat -n ipfw >/dev/null 2>&1; then echo "Existing IPFW: refusing host changes"; exit 1; fi
fetch -q -o "$base/endpoint.c" http://192.168.254.1:18066/endpoint.c
fetch -q -o "$base/delay-profile.txt" http://192.168.254.1:18066/profile
cc -O2 -Wall -Wextra -Werror -o "$base/endpoint" "$base/endpoint.c" > "$base/compiler.log" 2>&1
{ cc --version; sha256 "$base/endpoint.c" "$base/endpoint"; } >> "$base/compiler.log"
kenv net.inet.ip.fw.default_to_accept=1 > "$base/setup.log"
kenv_changed=1
for module in if_bridge if_epair nullfs ipfw dummynet; do
    if ! kldstat -n "$module" >/dev/null 2>&1; then
        kldload "$module" >> "$base/setup.log" 2>&1
        modules="$module $modules"
    fi
done
# The original host has no IPFW; loading starts with the recorded allow default.
ipfw list >> "$base/setup.log"
test "$(ipfw list | /usr/bin/grep -v '^65535 ' | wc -l | tr -d ' ')" = 0
ipfw list | /usr/bin/grep -q '65535 allow ip from any to any'
bridge=$(ifconfig bridge create)
ifconfig "$bridge" addm em0 up
for role in development reserved; do
    root="$base/$role/root"
    mkdir -p "$root/fixture" "$root/dev" "$root/libexec" "$root/usr/bin" "$root/usr/lib" "$root/etc"
    # IPFW resolves symbolic "tcp" using the jail's protocol database.
    cp /etc/protocols "$root/etc/protocols"
    chmod 444 "$root/etc/protocols"
    for path in bin sbin lib libexec usr/bin usr/lib; do
        mkdir -p "$root/$path"
        mount -t nullfs -o ro "/$path" "$root/$path"
        mounts="$root/$path $mounts"
    done
    mount -t devfs -o ruleset=4 devfs "$root/dev"
    mounts="$root/dev $mounts"
    cp "$base/endpoint" "$base/delay-profile.txt" "$root/fixture/"
    pair=$(ifconfig epair create)
    epairs="$pair $epairs"
    peer=$(printf '%s' "$pair" | sed 's/a$/b/')
    name="nyxr66_$role-$$"
    jail -c name="$name" path="$root" host.hostname="nyxr66-$role" persist vnet \
        vnet.interface="$peer" allow.raw_sockets=1
    jails="$name $jails"
    ifconfig "$pair" up
    ifconfig "$bridge" addm "$pair"
    # Static fixture addresses are outside Fusion's recorded DHCP pool.
    if test "$role" = development; then v4=192.168.254.66; v6=fd66:66:66::2; else v4=192.168.254.67; v6=fd66:66:66::3; fi
    jexec "$name" ifconfig lo0 127.0.0.1 up
    jexec "$name" ifconfig "$peer" inet "$v4/24" up
    jexec "$name" ifconfig "$peer" inet6 "$v6/64" alias
    jexec "$name" sysctl net.inet.ip.fw.enable=1 net.inet6.ip6.fw.enable=1 >> "$base/setup.log"
    sleep 2
    { echo "role=$role"; echo "jail=$name"; jexec "$name" ifconfig "$peer"; jexec "$name" netstat -rn; jexec "$name" ipfw list; } > "$base/$role/identity.txt"
    jexec "$name" /fixture/endpoint "$peer" "$v4" 192.168.254.1 "$v6" fd66:66:66::1 21600 > "$base/$role/endpoint.log" 2>&1 &
    pids="$! $pids"
done
sleep 2
tar -czf "$base/ready.tar.gz" -C "$base" host-before.txt setup.log compiler.log development/identity.txt \
    development/endpoint.log reserved/identity.txt reserved/endpoint.log
upload "$base/ready.tar.gz" /ready
echo "BSD development and reserved VNET fixtures listening; six-hour deadline"
for pid in $pids; do wait "$pid"; done
